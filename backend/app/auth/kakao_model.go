package auth

type KaKaoAccessTokenReq struct {
	IdToken string `json:"idToken"`
}

type KaKaoResponse struct {
	Id           string `json:"id"`
	KaKaoAccount struct {
		Email string `json:"email"`
	} `json:"kakao_account"`
}
