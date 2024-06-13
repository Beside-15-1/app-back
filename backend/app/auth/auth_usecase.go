package auth

import (
	"context"
	"crypto/rsa"
	"encoding/base64"
	"encoding/binary"
	"fmt"

	"joosum-backend/app/setting"
	"joosum-backend/app/user"
	localConfig "joosum-backend/pkg/config"
	"joosum-backend/pkg/util"
	"math/big"

	"github.com/go-resty/resty/v2"
	"github.com/golang-jwt/jwt/v4"
	"go.mongodb.org/mongo-driver/mongo"
	"google.golang.org/api/oauth2/v2"
	"google.golang.org/api/option"
)

type AuthUsecase struct {
	salt         string
	userModel    user.UserModel
	settingModel setting.SettingModel
	kakaoUsecase KakaoUsecase
	naverUsecae  NaverUsecae
}

func (u *AuthUsecase) GenerateNewJWTToken(email string) (string, string, error) {
	accessToken, err := util.GenerateNewJWTAccessToken([]util.Role{util.User}, email)
	if err != nil {
		return "", "", err
	}
	refreshToken, err := util.GenerateNewJWTRefreshToken()
	if err != nil {
		return "", "", err
	}

	return accessToken, refreshToken, nil
}

func (u *AuthUsecase) SignUp(userInfo user.User) (*user.User, error) {
	user, err := u.userModel.CreatUser(userInfo)
	if err != nil {
		return nil, err
	}
	return user, nil
}

func (u *AuthUsecase) Logout(userId string) (*mongo.UpdateResult, error) {
	result, err := u.settingModel.DeleteDivceId(userId)
	if err != nil {
		return nil, err
	}
	return result, nil
}

func (u *AuthUsecase) GetEmailFromJWT(social, idToken string) (string, error) {
	if social == "apple" {
		pubKey := ApplePublicKey{}
		publicSecret := PublicSecret{}
		client := resty.New()

		// 애플이 제공하는 public key 들을 가져옴
		pubKeyResult, err := client.R().SetResult(&pubKey).Get(ApplePublicKeyURL)
		JWKS := pubKeyResult.Result().(*ApplePublicKey)

		if err != nil {
			return "", fmt.Errorf("get apple public key err: %v", err)
		}

		claims := jwt.MapClaims{}
		_, err = jwt.ParseWithClaims(idToken, &claims, func(token *jwt.Token) (interface{}, error) {
			// kid 값 저장 | public key 대조에 필요하기 때문에
			kid := token.Header["kid"].(string)

			for _, v := range JWKS.Keys {
				// 받아온 public key 중 id_token 과 kid 일치하는지 확인 후 n, e 값 저장
				if kid == v.Kid {
					n, _ := base64.RawURLEncoding.DecodeString(v.N)
					publicSecret.N = n
					e, _ := base64.StdEncoding.DecodeString(v.E)
					publicSecret.E = e
					break
				}
			}
			publicKeyE := binary.LittleEndian.Uint32(append(publicSecret.E, 0))

			// 이 rsaKey 로 id_token verify
			rsaKey := &rsa.PublicKey{
				N: new(big.Int).SetBytes(publicSecret.N),
				E: int(publicKeyE),
			}
			return rsaKey, nil
		})
		email := claims["email"].(string)

		return email, nil
	} else if social == "google" {
		ctx := context.Background()

		oauth2Service, err := oauth2.NewService(ctx, option.WithAPIKey(localConfig.GetEnvConfig("googleApiKey")))
		if err != nil {
			return "", fmt.Errorf("unable to create OAuth2 service: %v", err)
		}

		tokenInfoCall := oauth2Service.Tokeninfo()
		tokenInfoCall.IdToken(idToken)

		tokenInfo, err := tokenInfoCall.Do()
		if err != nil {
			return "", fmt.Errorf("unable to verify IdToken: %v", err)
		}

		// Check if the token's audience matches your app's client ID.
		if tokenInfo.Audience != localConfig.GetEnvConfig("googleClientID") {
			return "", fmt.Errorf("IdToken is not issued by this app")
		}

		// Return the user's email address.
		if tokenInfo.Email != "" {
			return tokenInfo.Email, nil
		}

		return "", fmt.Errorf("unable to retrieve user's email")
	} else if social == "naver" {
		email, err := u.naverUsecae.GetUserEmailByToken(idToken)
		if err != nil {
			return "", err
		}
		return email, nil
	} else if social == "kakao" {
		email, err := u.kakaoUsecase.UserEmail(idToken)
		if err != nil {
			return "", err
		}
		return email, nil
	} else {
		return "", fmt.Errorf("invalid social name")
	}
}
