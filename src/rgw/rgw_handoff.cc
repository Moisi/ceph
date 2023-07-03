// -*- mode:C++; tab-width:8; c-basic-offset:2; indent-tabs-mode:t -*-
// vim: ts=8 sw=2 smarttab ft=cpp

#include "rgw_handoff.h"

#include <boost/algorithm/string.hpp>
#include <string>
#include <fmt/format.h>

#include "include/ceph_assert.h"

#include "common/dout.h"
#include "rgw/rgw_http_client_curl.h"

#define dout_subsys ceph_subsys_rgw

namespace ba = boost::algorithm;

namespace rgw {

int HandoffHelper::init(CephContext *const cct) {
	ldout(cct, 20) << "HandoffHelper::init" << dendl;
	return 0;
};

/**
 * @brief Prepare a JSON document to send to the authenticator.
 *
 * @param s Pointer to the req_state
 * @param full_url The generated request URL (XXX necessary?)
 * @param jf Ref to a JSONFormatter object that will receive the document.
 * @return int
 *
 * Construct a JSON string to send to the authenticator. With this we have
 * just enough information at this point to send to the authenticator so we
 * can securely construct and so validate an S3 v4 signature. We don't need
 * the access secret key, but the authenticator process does.
 *
 * ```json
 * {
 *   "stringToSign": ...,  // The string to sign field provided by rgw.
 *   "accessKeyId": ...,   // The access key, provided by rgw.
 *   "authorization": ...  // The Authorization: header of the HTTP message, verbatim.
 * }
 * ```
 */
static std::string PrepareHandoffRequest(const req_state *s, const std::string_view& string_to_sign, const std::string_view& access_key_id, const std::string_view& auth) {
	JSONFormatter jf{true};
	jf.open_object_section(""); // root
	encode_json("stringToSign", rgw::to_base64(string_to_sign), &jf);
	encode_json("accessKeyId", std::string(access_key_id), &jf);
	encode_json("authorization", std::string(auth), &jf);
	jf.close_section(); // root
	std::ostringstream oss;
	jf.flush(oss);
	return oss.str();
}


HandoffAuthResult HandoffHelper::auth(const DoutPrefixProvider *dpp,
	const std::string_view& session_token,
	const std::string_view& access_key_id,
	const std::string_view& string_to_sign,
	const std::string_view& signature,
	const req_state* const s,
	optional_yield y) {

	ldpp_dout(dpp, 10) << "HandoffHelper::auth()" << dendl;

	// The 'environment' of the request includes, amongst other things,
	// all the headers, prefixed with 'HTTP_'. They also have header names
	// uppercased and with underscores instead of hyphens.
	auto env = s->cio->get_env();

	// Retrieve the Authorization header which has a lot of fields we need.
	auto srch = env.get_map().find("HTTP_AUTHORIZATION");
	if (srch == env.get_map().end()) {
		ldpp_dout(dpp, 0) << "Handoff: Missing Authorization header, cannot continue" << dendl;
	}
	auto auth = srch->second;
	auto request_json = PrepareHandoffRequest(s, string_to_sign, access_key_id, auth);

	// Fetch the URI for the authentication REST endpoint.
	auto cct = dpp->get_cct();
	auto query_url = cct->_conf->rgw_handoff_uri;
	if (!ba::ends_with(query_url, "/")) {
		query_url += "/";
	}
	// The authentication verifier is a POST to /verify.
	query_url += "verify";

	ceph::bufferlist resp_bl;
	RGWHTTPTransceiver verify{cct, "POST", query_url, &resp_bl};
	verify.append_header("Content-Type", "application/json");
	verify.set_post_data(request_json);
	verify.set_send_length(request_json.length());

	ldpp_dout(dpp, 20) << fmt::format("fetch '{}': POST '{}'", query_url, request_json) << dendl;
	auto ret = verify.process(y);

	if (ret < 0) {
		ldpp_dout(dpp, 5) << fmt::format("fetch '{}' exit code {}", query_url, ret) << dendl;
		return HandoffAuthResult(-EACCES, fmt::format("Handoff query failed with code {}", ret));
	}

	// Parse useful information out of the response JSON.
	JSONParser parser;

	if (! parser.parse(resp_bl.c_str(), resp_bl.length())) {
		// Neutral error, the authentication system itself is failing.
		ldpp_dout(dpp, 0) << "Handoff response parser error: malformed JSON" << dendl;
		return HandoffAuthResult(-ERR_INTERNAL_ERROR, "malformed response JSON");
	}

	std::string message{"none"}; // Human-readable error message.
	std::string uid{"notset"}; // User id associated with the access key.

	try {
		JSONDecoder::decode_json("message", message, &parser, true);
		JSONDecoder::decode_json("uid", uid, &parser, true);
	} catch (const JSONDecoder::err& err) {
		ldpp_dout(dpp, 0) << fmt::format("Handoff response parser error: {}", err.what()) << dendl;
		return HandoffAuthResult(-ERR_INTERNAL_ERROR, message);
	}
	ldpp_dout(dpp, 20) << fmt::format("Handoff parser response: uid='{}' message='{}'", uid, message) << dendl;

	auto status = verify.get_http_status();
	ldpp_dout(dpp, 20) << fmt::format("fetch '{}' status {}", query_url, status) << dendl;

	// These error code responses mimic rgw_auth_keystone.cc.
	switch (status) {
	case 200:
		// Happy path.
		break;
	case 401:
		return HandoffAuthResult(-ERR_SIGNATURE_NO_MATCH, message);
	case 404:
		return HandoffAuthResult(-ERR_INVALID_ACCESS_KEY, message);
	case RGWHTTPClient::HTTP_STATUS_NOSTATUS:
		ldpp_dout(dpp, 5) << fmt::format("Handoff fetch '{}' unknown status {}", query_url, status) << dendl;
		return HandoffAuthResult(-EACCES, message);
	}

	return HandoffAuthResult(uid, message);
};

} /* namespace rgw */
