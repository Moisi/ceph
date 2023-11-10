/**
 * @file rgw_handoff_impl.cc
 * @author André Lucas (alucas@akamai.com)
 * @brief Implementation for rgw::HandoffHelper (PIMPL pattern).
 * @version 0.1
 * @date 2023-11-10
 *
 * @copyright Copyright (c) 2023
 *
 */

#include "rgw_handoff_impl.h"

#include <boost/algorithm/string.hpp>
#include <cstring>
#include <fmt/format.h>
#include <iostream>
#include <optional>
#include <string>
#include <string_view>

#include <time.h>

#include "include/ceph_assert.h"

#include "common/dout.h"
#include "rgw/rgw_http_client_curl.h"

#define dout_subsys ceph_subsys_rgw

namespace ba = boost::algorithm;

namespace rgw {

/**
 * @brief Prepare a JSON document to send to the authenticator.
 *
 * @param s Pointer to the req_state struct.
 * @param string_to_sign The pre-generated StringToSign field required by the
 * signature process.
 * @param access_key_id The access key ID. This is the Credential= field of
 * the Authorization header, but RGW has already parsed it out for us.
 * @param auth The full Authorization header in the HTTP request.
 * @param eak_param Optional EAK parameters.
 * @return std::string The JSON request as a (pretty-printed) string.
 *
 * Construct a JSON string to send to the authenticator. With this we have
 * just enough information at this point to send to the authenticator so we
 * can securely construct and so validate an S3 v4 signature. We don't need
 * the access secret key, but the authenticator process does.
 */
static std::string PrepareHandoffRequest(const req_state* s,
    const std::string_view& string_to_sign, const std::string_view& access_key_id,
    const std::string_view& auth, const std::optional<EAKParameters>& eak_param)
{
  JSONFormatter jf { true };
  jf.open_object_section(""); // root
  encode_json("stringToSign", rgw::to_base64(string_to_sign), &jf);
  encode_json("accessKeyId", std::string(access_key_id), &jf);
  encode_json("authorization", std::string(auth), &jf);
  if (eak_param && eak_param->valid()) {
    jf.open_object_section("eakParameters");
    encode_json("method", eak_param->method(), &jf);
    encode_json("bucketName", eak_param->bucket_name(), &jf);
    encode_json("objectKeyName", eak_param->object_key_name(), &jf);
    jf.close_section(); // /eakParameters
  }
  jf.close_section(); // /root
  std::ostringstream oss;
  jf.flush(oss);
  return oss.str();
}

/**
 * @brief Bundle the results from parsing the authenticator's JSON response.
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

  auto query_url = cct->_conf->rgw_handoff_http_uri;
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

/**
 * @brief Create an AWS v2 authorization header from the request's URL parameters.
 *
 * The v2 header form is generated by `s3cmd signurl` and `aws s3 presign`
 * when either no region is provided, or the region is us-east-1. It is simply:
 *
 * ```
 *   AWS <accesskeyid>:<signature>
 * ```
 *
 * Everything else required to check the signature will be provided to the
 * Authenticator in StringToSign.
 *
 * @param dpp DoutPrefixProvider.
 * @param s The request state.
 * @return std::optional<std::string> On failure, std::nullopt. On success,
 * the value for the Authorization: header.
 */
static std::optional<std::string> synthesize_v2_header(const DoutPrefixProvider* dpp, const req_state* s)
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

/**
 * @brief Create an AWS v4 authorization header from the request's URL
 * parameters.
 *
 * The V4 header form required the (long) credentials:
 *
 * ```
 *    <accesskeyid>/<region>/s3/aws_request
 * ```
 *
 * The SignedHeaders value, and the Signature value. These are formatted into:
 *
 * ```
 *    AWS4-HMAC-SHA256 Credential=<credentials>, SignedHeaders=<signedheader>, Signature=<signature>
 * ```
 *
 * We don't support signature v4A (ECDSA) at this time.
 *
 * @param dpp DoutPrefixProvider.
 * @param s The request state.
 * @return std::optional<std::string> On failure, std::nullopt. On success,
 * the value for the Authorization: header.
 */
static std::optional<std::string> synthesize_v4_header(const DoutPrefixProvider* dpp, const req_state* s)
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

std::optional<std::string> HandoffHelperImpl::synthesize_auth_header(
    const DoutPrefixProvider* dpp,
    const req_state* s)
{
  if (s->info.args.exists("AWSAccessKeyId")) {
    return synthesize_v2_header(dpp, s);
  }
  // Params starting with 'X-Amz' are lowercased.
  if (s->info.args.exists("x-amz-credential")) {
    return synthesize_v4_header(dpp, s);
  }
  return std::nullopt;
}

static std::optional<time_t> get_v4_presigned_expiry_time(const DoutPrefixProvider* dpp, const req_state* s)
{

  auto& argmap = s->info.args;
  auto maybe_date = argmap.get_optional("x-amz-date");
  if (!maybe_date) {
    ldpp_dout(dpp, 0) << "Missing x-amz-date parameter" << dendl;
  }
  auto maybe_expires_delta = argmap.get_optional("x-amz-expires");
  if (!maybe_expires_delta) {
    ldpp_dout(dpp, 0) << "Missing x-amz-expires parameter" << dendl;
  }
  if (!(maybe_date && maybe_expires_delta)) {
    return std::nullopt;
  }

  std::string date = std::move(*maybe_date);
  struct tm tm;
  memset(&tm, 0, sizeof(struct tm));
  char* p = strptime(date.c_str(), "%Y%m%dT%H%M%SZ", &tm);
  if (p == nullptr || *p != 0) {
    ldpp_dout(dpp, 0) << "Failed to parse x-amz-date parameter" << dendl;
    return std::nullopt;
  }
  time_t param_time = mktime(&tm);
  if (param_time == (time_t)-1) {
    ldpp_dout(dpp, 0) << "Error converting x-amz-date to unix time: " << strerror(errno) << dendl;
    return std::nullopt;
  }

  time_t expiry_time = param_time;
  std::string delta = std::move(*maybe_expires_delta);
  try {
    expiry_time += static_cast<time_t>(std::stoi(delta));
  } catch (std::exception& _) {
    ldpp_dout(dpp, 20) << "Failed to parse x-amz-expires" << dendl;
    return std::nullopt;
  }
  ldpp_dout(dpp, 20) << __func__ << fmt::format(": x-amz-date {}, delta {} -> unix time {}, expiry time {}", date, delta, param_time, expiry_time) << dendl;
  return std::make_optional(expiry_time);
}

static std::optional<time_t> get_v2_presigned_expiry_time(const DoutPrefixProvider* dpp, const req_state* s)
{
  auto& argmap = s->info.args;
  auto maybe_expires = argmap.get_optional("Expires");
  if (!maybe_expires) {
    ldpp_dout(dpp, 0) << "Missing Expiry parameter" << dendl;
    return std::nullopt;
  }

  auto expiry_time_str = maybe_expires.value();
  time_t expiry_time;
  try {
    expiry_time = std::stol(expiry_time_str, nullptr, 10);
  } catch (std::exception& _) {
    ldpp_dout(dpp, 0) << "Failed to parse presigned URL expiry time" << dendl;
    return false;
  }
  ldpp_dout(dpp, 20) << __func__ << ": expiry time " << expiry_time << dendl;
  return std::make_optional(expiry_time);
}

bool HandoffHelperImpl::valid_presigned_time(const DoutPrefixProvider* dpp, const req_state* s, time_t now)
{
  std::optional<time_t> maybe_expiry_time;

  auto& argmap = s->info.args;
  if (argmap.exists("AWSAccessKeyId")) {
    maybe_expiry_time = get_v2_presigned_expiry_time(dpp, s);
  } else if (argmap.exists("x-amz-credential")) {
    maybe_expiry_time = get_v4_presigned_expiry_time(dpp, s);
  }
  if (!maybe_expiry_time) {
    ldpp_dout(dpp, 0) << "Unable to extract presigned URL expiry time from query parameters" << dendl;
    return false;
  }
  ldpp_dout(dpp, 20) << fmt::format("Presigned URL last valid second {} now {}", *maybe_expiry_time, now) << dendl;
  if (*maybe_expiry_time < now) {
    ldpp_dout(dpp, 0) << fmt::format("Presigned URL expired - last valid second {} now {}", *maybe_expiry_time, now) << dendl;
    return false;
  }
  return true;
}

bool HandoffHelperImpl::is_eak_credential(const std::string_view access_key_id)
{
  using namespace std::string_view_literals;

  if (access_key_id.compare(0, 4, "OTv1"sv) == 0)
    return true;
  else {
    return false;
  }
}

HandoffAuthResult HandoffHelperImpl::auth(const DoutPrefixProvider* dpp,
    const std::string_view& session_token,
    const std::string_view& access_key_id,
    const std::string_view& string_to_sign,
    const std::string_view& signature,
    const req_state* const s,
    optional_yield y)
{

  ldpp_dout(dpp, 10) << "HandoffHelperImpl::auth()" << dendl;

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
    ldpp_dout(dpp, 20) << "HandoffHelperImpl::auth(): Authorization=" << auth << dendl;

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
    if (dpp->get_cct()->_conf->rgw_handoff_enable_presigned_expiry_check) {
      // Belt-and-braces: Check the expiry time.
      // Note that RGW won't (in v17.2.6) pass this to us; it checks the expiry
      // time before even calling auth(). Let's not assume things.
      if (!valid_presigned_time(dpp, s, time(nullptr))) {
        ldpp_dout(dpp, 0) << "Handoff: presigned URL expiry check failed" << dendl;
        return HandoffAuthResult(-EACCES, "Presigned URL expiry check failed");
      }
    }
  }

  // We might have disabled V2 signatures.
  if (!dpp->get_cct()->_conf->rgw_handoff_enable_signature_v2) {
    if (ba::starts_with(auth, "AWS ")) {
      ldpp_dout(dpp, 0) << "Handoff: V2 signatures are disabled, returning failure" << dendl;
      return HandoffAuthResult(-EACCES, "Access denied (V2 signatures disabled)");
    }
  }

  // Only do the extra work for EAK if we have to, i.e. the access key looks
  // like an EAK variant.
  //
  std::optional<EAKParameters> eak_param;
  if (is_eak_credential(access_key_id)) {
    ldpp_dout(dpp, 20) << "Handoff: Gathering request info for EAK" << dendl;
    eak_param = EAKParameters(dpp, s);
    ldpp_dout(dpp, 20) << eak_param << dendl;
    if (!(eak_param->valid())) {
      // This shouldn't happen with a valid request. If it does, it's probably
      // a bug.
      ldpp_dout(dpp, 0) << "Handoff: EAK request info fetch failed (likely BUG)" << dendl;
      return HandoffAuthResult(-EACCES, "Access denied (failed to fetch request info for EAK credential)");
    }
  }

  // Build our JSON request for the authenticator.
  auto request_json = PrepareHandoffRequest(s, string_to_sign, access_key_id, auth, eak_param);

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
  default:
    ldpp_dout(dpp, 0) << fmt::format("Handoff fetch '{}' returned unexpected HTTP status code {}", status) << dendl;
    return HandoffAuthResult(-EACCES, resp.message);
  }

  return HandoffAuthResult(resp.uid, resp.message);
};

} // namespace rgw
