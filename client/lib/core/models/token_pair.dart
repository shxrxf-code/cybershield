/// `TokenResponse` from `POST /api/v1/auth/login` and `/auth/refresh`.
library;

import '../utils/json.dart';

class TokenPair {
  const TokenPair({
    required this.accessToken,
    required this.refreshToken,
    this.expiresIn = 0,
    this.refreshExpiresIn = 0,
  });

  final String accessToken;
  final String refreshToken;
  final int expiresIn;
  final int refreshExpiresIn;

  factory TokenPair.fromJson(Map<String, dynamic> json) => TokenPair(
        accessToken: asStringOr(json['access_token'], ''),
        refreshToken: asStringOr(json['refresh_token'], ''),
        expiresIn: asInt(json['expires_in']),
        refreshExpiresIn: asInt(json['refresh_expires_in']),
      );
}