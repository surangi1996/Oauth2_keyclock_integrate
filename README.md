# Oauth2_keyclock_integrate
```import 'dart:html';
import 'dart:io';
import 'dart:developer';
import 'dart:math' as math;

import 'package:flutter/foundation.dart';
import 'package:auto_route/auto_route.dart';
import 'package:dio/dio.dart';
import 'package:flutter/material.dart';
import 'package:get/get.dart';
import 'package:openid_client/openid_client.dart';
import 'package:openid_client/openid_client_io.dart' as openid_io;
import 'package:openid_client/openid_client_browser.dart' as openid_browser;
import 'package:oauth2/oauth2.dart' as oauth2;
import 'package:soff_cricket_hybrid/models/user/user_model.dart';
import 'package:soff_cricket_hybrid/routes/guards/auth_guard.dart';
import 'package:soff_cricket_hybrid/services/auth/token_manager_service.dart';
import 'package:soff_cricket_hybrid/services/auth/user_manager_service.dart';
import 'package:soff_cricket_hybrid/services/customer_service.dart';
import 'package:soff_cricket_hybrid/utils/datetime_utils/datetime_util.dart';
import 'package:soff_cricket_hybrid/views/_shared/constants/app_constants.dart';
import 'package:soff_cricket_hybrid/views/_shared/widget/toast.dart';
import 'package:url_launcher/url_launcher.dart';

class KeyCloakAuthService extends FullLifeCycleController {
  static final Uri uri = Uri.https("auth2.gangfy.com", "/auth/realms/gangfy");
  static const String clientId = "gangfy_booking";
  static final scopes = ['openid', 'profile', 'email', 'offline_access'];
  static final authorizationEndpoint = Uri.parse(
      "https://auth2.gangfy.com/auth/realms/gangfy/protocol/openid-connect/auth");
  static final tokenEndpoint = Uri.parse(
      "https://auth2.gangfy.com/auth/realms/gangfy/protocol/openid-connect/token");

  static Future<Credential> authenticate() async {
    if (kIsWeb) {
      return await authenticateWeb();
    } else {
      return await authenticateMobile();
    }
  }

  // Method for mobile
  static Future<openid_io.Credential> authenticateMobile() async {
    var issuer = await Issuer.discover(uri);
    var client = openid_io.Client(issuer, clientId);

    urlLauncher(String url) async {
      if (await canLaunchUrl(Uri.parse(url))) {
        await launchUrl(Uri.parse(url),
            webViewConfiguration:
                const WebViewConfiguration(enableJavaScript: true));
      } else {
        throw 'Could not launch $url';
      }
    }

    var authenticator = openid_io.Authenticator(
      client,
      scopes: scopes,
      port: 4200,
      urlLancher: urlLauncher,
      // redirectUri: redirectUri
    );

    var c = await authenticator.authorize();
    closeInAppWebView(); // Assuming you have this method
    return c;
  }

  static const String _charset =
      'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~';

  static String _createCodeVerifier() {
    return List.generate(
            128, (i) => _charset[math.Random.secure().nextInt(_charset.length)])
        .join();
  }

  // Method for web
  static Future<openid_browser.Credential> authenticateWeb() async {
    var redirectUrl = Uri.parse(window.location.origin);
    redirectUrl = redirectUrl.replace(path: "callback");

    if (window.sessionStorage.containsKey("auth_callback_response_url") &&
        window.sessionStorage.containsKey("auth_code_verifier")) {
      var grant = oauth2.AuthorizationCodeGrant(
          clientId, authorizationEndpoint, tokenEndpoint,
          codeVerifier: window.sessionStorage["auth_code_verifier"]);

      var authorizationUrl =
          grant.getAuthorizationUrl(redirectUrl, scopes: scopes);
      var responseUrl =
          Uri.parse(window.sessionStorage["auth_callback_response_url"] ?? '');
      // window.sessionStorage.remove("auth_callback_response_url");
      var client =
          await grant.handleAuthorizationResponse(responseUrl.queryParameters);
      log("xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx");
      log(client.identifier ?? '');
      log(client.credentials.toString());
      log(client.secret ?? '');
    } else {
      final codeVerifier = _createCodeVerifier();
      window.sessionStorage["auth_code_verifier"] = codeVerifier;

      var grant = oauth2.AuthorizationCodeGrant(
        clientId,
        authorizationEndpoint,
        tokenEndpoint,
        codeVerifier: codeVerifier,
      );

      // saveCodeVerifier(codeVerifier);

      var authorizationUrl =
          grant.getAuthorizationUrl(redirectUrl, scopes: scopes);

      window.location.href = authorizationUrl.toString();
    }

    throw "Authenticate";

    // var credential = Credential
  }

  static refreshToken() async {
    if (isTokenExpired()) {
      toastBottomSuccess(AppConstants.sessionExpiredWarningMessage);
      var dio = Dio();
      TokenManager _tokenManager = Get.find<TokenManager>();
      String? refreshToken = _tokenManager.getRefreshToken();

      Map<String, dynamic> requestBody = {
        'grant_type': 'refresh_token',
        'client_id': 'gangfy_booking',
        'refresh_token': refreshToken!
      };

      try {
        var response = await dio.post(
          'https://auth2.gangfy.com/auth/realms/gangfy/protocol/openid-connect/token',
          data: requestBody,
          options: Options(contentType: Headers.formUrlEncodedContentType),
        );

        if (response.statusCode == HttpStatus.ok) {
          int _expiresIn = response.data['expires_in'];
          DateTime _updatedExpiryAt =
              DateTimeUtil.addTimeToCurrentTime(_expiresIn ~/ 60);
          _tokenManager.setExpiryTime(_updatedExpiryAt);
          _tokenManager.setAccessTokens(response.data['access_token']);
          _tokenManager.setRefreshToken(response.data['refresh_token']);
        }
      } on DioError catch (e) {
        toastBottomSuccess(AppConstants.sessionExpiredWarningMessage);
        login();
      }
    }
  }

  static bool isTokenExpired() {
    TokenManager _tokenManager = Get.find<TokenManager>();
    String? expiryTime = _tokenManager.getExpiryTime();
    return DateTimeUtil.isTimeExpired(expiryTime.toString());
  }

  static Future<bool> login() async {
    try {
      UserManager _userManager = Get.find<UserManager>();
      TokenManager _tokenManager = Get.find<TokenManager>();
      _tokenManager.removeTokens();

      Credential credential = await KeyCloakAuthService.authenticate();
      TokenResponse tokenResponse = await credential.getTokenResponse();

      if (!tokenResponse.isBlank!) {
        UserInfo userInfo = await credential.getUserInfo();

        _tokenManager.setAccessTokens(tokenResponse.accessToken!);
        _tokenManager.setRefreshToken(tokenResponse.refreshToken!);
        _tokenManager.setIdToken(tokenResponse['id_token']);
        _tokenManager.setExpiryTime(tokenResponse.expiresAt!);
        _userManager.setUserName(userInfo.email!);
        _tokenManager.setEmailVerification(userInfo.emailVerified!);

        var apiResponse =
            await CustomerService().getCustomerByEmail(userInfo.email!);

        if (apiResponse.status) {
          await _userManager.setUserData(apiResponse.data);
        } else {
          var user = UserModel(
              firstName: userInfo.givenName!,
              lastName: userInfo.familyName!,
              email: userInfo.email!);
          await _userManager.setUserData(user);
        }

        toastBottomSuccess(AppConstants.loginSuccessMessage);
        AuthGuard().afterLogIn();
        return true;
      }
      throw Exception(AppConstants.keycloakErrorMessage);
      // ignore: unused_catch_clause
    } on Exception catch (e) {
      toastBottomSuccess(AppConstants.applicationErrorMessage);
      return false;
    }
  }

  static Future<bool> logOut(BuildContext buildContext) async {
    AuthGuard().afterLogout();
    AutoRouter.of(buildContext).popUntilRoot();
    try {
      UserManager _userManager = Get.find<UserManager>();
      _userManager.onDelete();
      _userManager.reset();
      var uri = Uri.https("auth2.gangfy.com", "/auth/realms/gangfy"); // auth2
      var issuer = await Issuer.discover(uri);
      var client = Client(issuer, "gangfy_booking");

      TokenManager _tokenManager = Get.find<TokenManager>();

      Credential credential = client.createCredential(
        tokenType: 'Bearer',
        refreshToken: _tokenManager.getRefreshToken(),
        idToken: _tokenManager.getIdToken(),
      );

      Uri? logOutUri = credential.generateLogoutUrl();

      urlLauncher(Uri? url) async {
        if (url == null) return;
        if (await canLaunchUrl(url)) {
          await launchUrl(url,
              webViewConfiguration:
                  const WebViewConfiguration(enableJavaScript: true));
        } else {
          throw 'Could not launch $url';
        }
      }

      _tokenManager.removeTokens();

      urlLauncher.call(logOutUri);
      login();
    } catch (e) {
      // ignore: avoid_print
      print(e);
    }
    return true;
  }
}
```
