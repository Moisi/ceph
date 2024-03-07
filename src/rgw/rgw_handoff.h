// -*- mode:C++; tab-width:8; c-basic-offset:2; indent-tabs-mode:t -*-
// vim: ts=8 sw=2 smarttab ft=cpp

/**
 * @file rgw_handoff.cc
 * @author André Lucas (alucas@akamai.com)
 * @brief 'Handoff' S3 authentication engine.
 * @version 0.1
 * @date 2023-07-04
 *
 * Persistent 'helper' class for the Handoff authentication engine for S3.
 * This allows us to keep items such as a pointer to the store abstraction
 * layer and a gRPC channel around between requests.
 *
 * HandoffHelper simply wraps HandoffHelperImpl. Keep the number of classes in
 * this file to a strict minimum - most should be in rgw_handoff_impl.{h,cc}.
 *
 * DO NOT INCLUDE "rgw_handoff_impl.h" from here!
 */

#ifndef RGW_HANDOFF_H
#define RGW_HANDOFF_H

#include <fmt/format.h>
#include <iosfwd>
#include <string>

#include "common/async/yield_context.h"
#include "common/dout.h"
#include "rgw/rgw_common.h"

namespace rgw {

/**
 * @brief Return type of the HandoffHelper auth() method.
 *
 * Encapsulates either the return values we need to continue on successful
 * authentication, or a failure code.
 */
class HandoffAuthResult {
public:
  /**
   * @brief Classification of error-type results, to help with logging.
   */
  enum class error_type {
    NO_ERROR,
    TRANSPORT_ERROR,
    AUTH_ERROR,
    INTERNAL_ERROR,
  };

  enum class user_type {
    USER,
    ANONYMOUS,
  };

public:
  /**
   * @brief Construct a success-type result for a regular user.
   *
   * @param userid The user ID associated with the request.
   * @param message human-readable status.
   */
  HandoffAuthResult(const std::string& userid, const std::string& message)
      : userid_ { userid }
      , message_ { message }
      , is_err_ { false }
      , err_type_ { error_type::NO_ERROR } {};

  /**
   * @brief Construct a success-type result for an anonymous user.
   *
   * @param type user_type::ANONYMOUS
   * @param message human-readable status.
   */
  HandoffAuthResult(user_type type, const std::string& message)
      : type_ { user_type::ANONYMOUS }
      , userid_ {}
      , message_ { message }
      , is_err_ { false }
      , err_type_ { error_type::NO_ERROR }
  {
    if (type != user_type::ANONYMOUS) {
      throw std::invalid_argument("HandoffAuthResult: type must be ANONYMOUS");
    }
  };

  /**
   * @brief Construct a success-type result. \p message is
   *
   * \p errorcode is one of the codes in rgw_common.cc, array
   * rgw_http_s3_errors. If we don't map exactly, it's most likely because
   * those error codes don't match the HTTP return code we want.
   *
   * @param errorcode The RGW S3 error code.
   * @param message human-readable status.
   * @param err_type The error type enum, which will help give better error
   * log messages.
   */
  HandoffAuthResult(int errorcode, const std::string& message, error_type err_type = error_type::AUTH_ERROR)
      : errorcode_ { errorcode }
      , message_ { message }
      , is_err_ { true }
      , err_type_ { err_type } {};

  bool is_anonymous() const noexcept { return type_ == user_type::ANONYMOUS; }
  bool is_err() const noexcept { return is_err_; }
  bool is_ok() const noexcept { return !is_err_; }
  error_type err_type() const noexcept { return err_type_; }
  int code() const noexcept { return errorcode_; }
  std::string message() const noexcept { return message_; }

  /// @brief Return the user ID for a success result. Throw EACCES on
  /// failure.
  ///
  /// This is to catch erroneous use of userid(). It will probably get
  /// thrown all the way up to rgw::auth::Strategy::authenticate().
  std::string userid() const
  {
    if (is_err()) {
      throw -EACCES;
    }
    return userid_;
  }

  std::string to_string() const noexcept
  {
    if (is_err()) {
      return fmt::format(FMT_STRING("error={} message={}"), errorcode_, message_);
    } else {
      if (is_anonymous()) {
        return fmt::format(FMT_STRING("(anonymous) message={}"), message_);
      } else {
        return fmt::format(FMT_STRING("userid='{}' message={}"), userid_, message_);
      }
    }
  }

  friend std::ostream& operator<<(std::ostream& os, const HandoffAuthResult& ep);

private:
  user_type type_ = user_type::USER;
  std::string userid_
      = "";
  int errorcode_ = 0;
  std::string message_ = "";
  bool is_err_ = false;
  error_type err_type_ = error_type::NO_ERROR;
};

class HandoffHelperImpl; // Forward declaration.

/**
 * @brief Support class for 'handoff' authentication.
 *
 * Used by rgw::auth::s3::HandoffEngine to implement authentication via an
 * external REST service. Note this is essentially a wrapper class - the work
 * is all done in rgw::HandoffHelperImpl, to keep the gRPC headers away from
 * the rest of RGW.
 */
class HandoffHelper {

private:
  /* There's some trouble taken to make a smart pointer to an incomplete
   * object work properly. See notes around the destructor declaration and
   * definition, it's subtle.
   */
  std::unique_ptr<HandoffHelperImpl> impl_;

public:
  /*
   * Implementation note: We need to implement the constructor(s) and
   * destructor when we know the size of HandoffHelperImpl. This means we
   * implement in the .cc file, which _does_ include the impl header file.
   * *Don't* include the impl header file in this .h, and don't switch to
   * using the default implementation - it won't compile.
   */

  HandoffHelper();

  ~HandoffHelper();

  /**
   * @brief Initialise any long-lived state for this engine.
   * @param cct Pointer to the Ceph context.
   * @param store Pointer to the sal::Store object.
   * @return 0 on success, otherwise failure.
   *
   * Initialise the long-lived object. Calls HandoffHelperImpl::init() and
   * returns its result.
   */
  int init(CephContext* const cct, rgw::sal::Driver* store);

  /**
   * @brief Authenticate the transaction using the Handoff engine.
   * @param dpp Debug prefix provider. Points to the Ceph context.
   * @param session_token Unused by Handoff.
   * @param access_key_id The S3 access key.
   * @param string_to_sign The canonicalised S3 signature input.
   * @param signature The transaction signature provided by the user.
   * @param s Pointer to the req_state.
   * @param y An optional yield token.
   * @return A HandofAuthResult encapsulating a return error code and any
   * parameters necessary to continue processing the request, e.g. the uid
   * associated with the access key.
   *
   * Simply calls the HandoffHelperImpl::auth() and returns its result.
   */
  HandoffAuthResult auth(const DoutPrefixProvider* dpp,
      const std::string_view& session_token,
      const std::string_view& access_key_id,
      const std::string_view& string_to_sign,
      const std::string_view& signature,
      const req_state* const s,
      optional_yield y);
};

} /* namespace rgw */

#endif /* RGW_HANDOFF_H */
