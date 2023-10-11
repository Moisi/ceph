// -*- mode:C++; tab-width:8; c-basic-offset:2; indent-tabs-mode:t -*-
// vim: ts=8 sw=2 smarttab ft=cpp

/**
 * @file rgw_handoff.cc
 * @author André Lucas (andre.lucas@storageos.com)
 * @brief 'Handoff' S3 authentication engine.
 * @version 0.1
 * @date 2023-07-04
 */

/* References are to the AWS Signature Version 4 documentation:
 *   https://docs.aws.amazon.com/AmazonS3/latest/API/sig-v4-authenticating-requests.html
 */

#include "rgw_handoff.h"

#include <boost/algorithm/string.hpp>
#include <cstring>
#include <fmt/format.h>
#include <optional>
#include <string>

#include "include/ceph_assert.h"

#include "common/dout.h"
#include "rgw/rgw_http_client_curl.h"

#define dout_subsys ceph_subsys_rgw

namespace ba = boost::algorithm;

namespace rgw {

int HandoffHelper::init(CephContext* const cct)
{
  ldout(cct, 20) << "HandoffHelper::init" << dendl;
  return 0;
};

/**
 * @brief Prepare a JSON document to send to the authenticator.
 *
 * @param s Pointer to the req_state struct.
 * @param string_to_sign The pre-generated StringToSign field required by the
 * signature process.
 * @param access_key_id The access key ID. This is the Credential= field of
 * the Authorization header, but RGW has already parsed it out for us.
 * @param auth The full Authorization header in the HTTP request.
 * @return std::string The JSON request as a (pretty-printed) string.
 *
 * Construct a JSON string to send to the authenticator. With this we have
 * just enough information at this point to send to the authenticator so we
 * can securely construct and so validate an S3 v4 signature. We don't need
 * the access secret key, but the authenticator process does.
 */
static std::string PrepareHandoffRequest(const req_state* s, const std::string_view& string_to_sign, const std::string_view& access_key_id, const std::string_view& auth)
{
  JSONFormatter jf { true };
  jf.open_object_section(""); // root
  encode_json("stringToSign", rgw::to_base64(string_to_sign), &jf);
  encode_json("accessKeyId", std::string(access_key_id), &jf);
  encode_json("authorization", std::string(auth), &jf);
  jf.close_section(); // root
  std::ostringstream oss;
  jf.flush(oss);
  return oss.str();
}

/**
 * @brief Bundle the results form parsing the authenticator's JSON response.
 *
 * \p uid has meaning only when \p success is true. If success is false, \p
 * uid's value must not be used.
 *
 * In all cases, \p message may contain human-readable information to help
 * explain the result.
 */
struct HandoffResponse {
  bool success;
  std::string uid;
  std::string message;
};

/**
 * @brief Parse the authenticator's JSON response.
 *
 * @param dpp The *DoutPrefixProvider passed to the engine.
 * @param resp_bl The ceph::bufferlist used by the RGWHTTPClient subclass.
 * @return HandoffResponse Parser result.
 *
 * This merely attempts to parse the JSON response from the authenticator.
 * Field \p success of the return struct is set last, and if it's false the
 * caller MUST assume authentication failure.
 */
static HandoffResponse ParseHandoffResponse(const DoutPrefixProvider* dpp, ceph::bufferlist& resp_bl)
{
  HandoffResponse resp { success : false, uid : "notset", message : "none" };

  JSONParser parser;

  if (!parser.parse(resp_bl.c_str(), resp_bl.length())) {
    ldpp_dout(dpp, 0) << "Handoff response parser error: malformed JSON" << dendl;
    resp.message = "malformed response JSON";
    return resp;
  }

  try {
    JSONDecoder::decode_json("message", resp.message, &parser, true);
    JSONDecoder::decode_json("uid", resp.uid, &parser, true);
  } catch (const JSONDecoder::err& err) {
    ldpp_dout(dpp, 0) << fmt::format("Handoff response parser error: {}", err.what()) << dendl;
    return resp;
  }
  ldpp_dout(dpp, 20) << fmt::format("Handoff parser response: uid='{}' message='{}'", resp.uid, resp.message) << dendl;
  resp.success = true;
  return resp;
}

static HandoffVerifyResult verify_standard(const DoutPrefixProvider* dpp, const std::string& request_json, bufferlist* resp_bl, optional_yield y)
{
  auto cct = dpp->get_cct();

  auto query_url = cct->_conf->rgw_handoff_uri;
  if (!ba::ends_with(query_url, "/")) {
    query_url += "/";
  }
  // The authentication verifier is a POST to /verify.
  query_url += "verify";

  RGWHTTPTransceiver verify { cct, "POST", query_url, resp_bl };
  verify.set_verify_ssl(cct->_conf->rgw_handoff_verify_ssl);
  verify.append_header("Content-Type", "application/json");
  verify.set_post_data(request_json);
  verify.set_send_length(request_json.length());

  ldpp_dout(dpp, 20) << fmt::format("fetch '{}': POST '{}'", query_url, request_json) << dendl;
  auto ret = verify.process(y);

  return HandoffVerifyResult { ret, verify.get_http_status(), query_url };
}

std::optional<std::string> HandoffHelper::synthesize_v2_header(const DoutPrefixProvider* dpp, const req_state* s)
{
  auto& infomap = s->info.args;
  auto maybe_credential = infomap.get_optional("AWSAccessKeyId");
  if (!maybe_credential) {
    ldpp_dout(dpp, 0) << "Missing AWSAccessKeyId parameter" << dendl;
  }
  auto maybe_signature = infomap.get_optional("Signature");
  if (!maybe_signature) {
    ldpp_dout(dpp, 0) << "Missing Signature parameter" << dendl;
  }
  if (!(maybe_credential && maybe_signature)) {
    return std::nullopt;
  }
  return std::make_optional(fmt::format("AWS {}:{}",
      *maybe_credential, *maybe_signature));
}

std::optional<std::string> HandoffHelper::synthesize_v4_header(const DoutPrefixProvider* dpp, const req_state* s)
{
  auto& infomap = s->info.args;

  // Params starting with 'X-Amz' are lowercased.
  auto maybe_credential = infomap.get_optional("x-amz-credential");
  if (!maybe_credential) {
    ldpp_dout(dpp, 0) << "Missing x-amz-credential parameter" << dendl;
  }
  auto maybe_signedheaders = infomap.get_optional("x-amz-signedheaders");
  if (!maybe_signedheaders) {
    ldpp_dout(dpp, 0) << "Missing x-amz-signedheaders parameter" << dendl;
  }
  auto maybe_signature = infomap.get_optional("x-amz-signature");
  if (!maybe_signature) {
    ldpp_dout(dpp, 0) << "Missing x-amz-signature parameter" << dendl;
  }
  if (!(maybe_credential && maybe_signedheaders && maybe_signature)) {
    return std::nullopt;
  }
  return std::make_optional(fmt::format("AWS4-HMAC-SHA256 Credential={}, SignedHeaders={}, Signature={}",
      *maybe_credential, *maybe_signedheaders, *maybe_signature));
}

std::optional<std::string> HandoffHelper::synthesize_auth_header(
    const DoutPrefixProvider* dpp,
    const req_state* s)
{
  if (s->info.args.get_optional("AWSAccessKeyId")) {
    return synthesize_v2_header(dpp, s);
  }
  // Params starting with 'X-Amz' are lowercased.
  if (s->info.args.get_optional("x-amz-credential")) {
    return synthesize_v4_header(dpp, s);
  }
  return std::nullopt;
}

// Documentation in .h.
HandoffAuthResult HandoffHelper::auth(const DoutPrefixProvider* dpp,
    const std::string_view& session_token,
    const std::string_view& access_key_id,
    const std::string_view& string_to_sign,
    const std::string_view& signature,
    const req_state* const s,
    optional_yield y)
{

  ldpp_dout(dpp, 10) << "HandoffHelper::auth()" << dendl;

  if (!s->cio) {
    return HandoffAuthResult(-EACCES, "Internal error (cio)");
  }
  // The 'environment' of the request includes, amongst other things,
  // all the headers, prefixed with 'HTTP_'. They also have header names
  // uppercased and with underscores instead of hyphens.
  auto envmap = s->cio->get_env().get_map();

  // Retrieve the Authorization header which has a lot of fields we need.
  std::string auth;
  auto srch = envmap.find("HTTP_AUTHORIZATION");
  if (srch != envmap.end()) {
    auth = srch->second;
    ldpp_dout(dpp, 20) << "HandoffHelper::auth(): Authorization=" << auth << dendl;

  } else {
    // Attempt to create an Authorization header using query parameters.
    auto maybe_auth = synthesize_auth_header(dpp, s);
    if (maybe_auth) {
      auth = std::move(*maybe_auth);
      ldpp_dout(dpp, 20) << "Synthesized Authorization=" << auth << dendl;
    } else {
      ldpp_dout(dpp, 0) << "Handoff: Missing Authorization header and insufficient query parameters" << dendl;
      return HandoffAuthResult(-EACCES, "Internal error (missing Authorization and insufficient query parameters)");
    }
  }

  // We might have disabled V2 signatures.
  if (!dpp->get_cct()->_conf->rgw_handoff_enable_signature_v2) {
    if (ba::starts_with(auth, "AWS ")) {
      ldpp_dout(dpp, 0) << "Handoff: V2 signatures are disabled, returning failure" << dendl;
      return HandoffAuthResult(-EACCES, "Access denied (V2 signatures disabled)");
    }
  }

  // Build our JSON request for the authenticator.
  auto request_json = PrepareHandoffRequest(s, string_to_sign, access_key_id, auth);

  ceph::bufferlist resp_bl;

  HandoffVerifyResult vres;
  // verify_func_ is initialised at construction time and is const, we *do
  // not* need to synchronise access.
  if (verify_func_) {
    vres = (*verify_func_)(dpp, request_json, &resp_bl, y);
  } else {
    vres = verify_standard(dpp, request_json, &resp_bl, y);
  }

  if (vres.result() < 0) {
    ldpp_dout(dpp, 0) << fmt::format("handoff verify HTTP request failed with exit code {} ({})", vres.result(), strerror(-vres.result()))
                      << dendl;
    return HandoffAuthResult(-EACCES, fmt::format("Handoff HTTP request failed with code {} ({})", vres.result(), strerror(-vres.result())));
  }

  // Parse the JSON response.
  auto resp = ParseHandoffResponse(dpp, resp_bl);
  if (!resp.success) {
    // Neutral error, the authentication system itself is failing.
    return HandoffAuthResult(-ERR_INTERNAL_ERROR, resp.message);
  }

  // Return an error, but only after attempting to parse the response
  // for a useful error message.
  auto status = vres.http_code();
  ldpp_dout(dpp, 20) << fmt::format("fetch '{}' status {}", vres.query_url(), status) << dendl;

  // These error code responses mimic rgw_auth_keystone.cc.
  switch (status) {
  case 200:
    // Happy path.
    break;
  case 401:
    return HandoffAuthResult(-ERR_SIGNATURE_NO_MATCH, resp.message);
  case 404:
    return HandoffAuthResult(-ERR_INVALID_ACCESS_KEY, resp.message);
  case RGWHTTPClient::HTTP_STATUS_NOSTATUS:
    ldpp_dout(dpp, 5) << fmt::format("Handoff fetch '{}' unknown status {}", vres.query_url(), status) << dendl;
    return HandoffAuthResult(-EACCES, resp.message);
  }

  return HandoffAuthResult(resp.uid, resp.message);
};

} /* namespace rgw */
