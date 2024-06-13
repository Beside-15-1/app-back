package auth

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
)

type KakaoUsecase struct {
}

// google 의 golang 가이드라인을 한 번 봤는데
// 거기에서 Get은 최대한 쓰지 마라고 해서 Get 부분 뻄
// https://go.dev/doc/effective_go#Getters
// 사용하는 매게 변수 반복하지마라
// https://google.github.io/styleguide/go/best-practices
// GetUserEmailByToken 을 UserEmail 로 변경 했다고 보면 됩니다.

func (k *KakaoUsecase) UserEmail(accessToken string) (string, error) {
	const endpoint = "https://kapi.kakao.com/v2/user/me"

	// Create a new request to the specified endpoint
	req, err := http.NewRequest("GET", endpoint, nil)
	if err != nil {
		return "", err
	}

	// Set the Authorization header with the access token
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", accessToken))

	// Send the request
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	// Read and parse the response
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	var naverResp NaverResponse
	if err = json.Unmarshal(body, &naverResp); err != nil {
		return "", err
	}

	// Check if the message is not "success"
	if naverResp.Resultcode != "00" || naverResp.Message != "success" {
		return "", fmt.Errorf("failed to retrieve the email from Naver")
	}

	return naverResp.Response.Email, nil
}
