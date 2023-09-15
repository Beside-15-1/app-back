package link

import (
	"joosum-backend/app/user"
	"net/http"

	"github.com/gin-gonic/gin"
)

type LinkHandler struct {
	linkUsecase LinkUsecase
}

type CreateLinkReq struct {
	URL          string   `json:"url"`
	Title        string   `json:"title"`
	LinkBookId   string   `json:"linkBookId"`
	ThumbnailURL string   `json:"thumbnailURL"`
	Tags         []string `json:"tags"`
}

type UpdateLinkReq struct {
	Title        string   `json:"title"`
	URL          string   `json:"url"`
	ThumbnailURL string   `json:"thumbnailURL"`
	Tags         []string `json:"tags"`
}

// CreateLink
// @Tags 링크
// @Summary 링크 생성
// @Description 링크 생성 만약에 기본 링크북에 저장하고 싶다면, linkBookId 에 빈스트링 혹은 root 라고 넣어주세요.
// @Accept json
// @Produce json
// @Security ApiKeyAuth
// @Param request body CreateLinkReq true "링크 생성 요청 본문"
// @Success 200 {object} Link "링크 생성이 성공적으로 이루어졌을 때 새로 생성된 링크 객체 반환"
// @Failure 400 {object} util.APIError "요청 본문이 유효하지 않을 때 반환합니다."
// @Failure 401 {object} util.APIError "Authorization 헤더가 없을 때 반환합니다."
// @Failure 500 {object} util.APIError "링크 생성 과정에서 오류가 발생한 경우 반환합니다."
// @Security ApiKeyAuth
// @Router /links [post]
func (h LinkHandler) CreateLink(c *gin.Context) {
	currentUser, exists := c.Get("user")
	if !exists {
		// 401 Unauthorized
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Missing Authorization header"})
		return
	}

	userId := currentUser.(*user.User).UserId

	var req CreateLinkReq
	if err := c.ShouldBindJSON(&req); err != nil {
		// 400 Bad Request
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request body"})
		return
	}

	link, err := h.linkUsecase.CreateLink(req.URL, req.Title, userId, req.LinkBookId, req.ThumbnailURL, req.Tags)
	if err != nil {
		// 500 Internal Server Error
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	// 200 OK
	c.JSON(http.StatusOK, link)
}

// GetLinks godoc
// @Tags 링크
// @Summary 링크를 조회합니다.
// @Description 사용자 아이디를 통해 해당 사용자의 모든 링크를 조회합니다. Sort를 Query Parameter로 받아서 정렬할 수 있습니다. Search로 검색할 수 있습니다.
// @Accept  json
// @Produce  json
// @Security ApiKeyAuth
// @Param sort query string false "정렬 기준" Enums(created_at,updated_at,title)
// @Param order query string false "정렬 순서" Enums(asc,desc)
// @Param search query string false "검색어"
// @Success 200 {object} Link "나의 유저아이디 기반으로 모든 링크를 반환합니다."
// @Failure 401 {object} util.APIError "Authorization 헤더가 없을 때 반환합니다."
// @Router /links [get]
func (h LinkHandler) GetLinks(c *gin.Context) {
	currentUser, exists := c.Get("user")

	if !exists {
		// 401 Unauthorized
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Missing Authorization header"})
		return
	}

	userId := currentUser.(*user.User).UserId

	sort := c.Query("sort")
	order := c.Query("order")

	if sort == "" {
		sort = "created_at"
	}

	if order == "" {
		order = "asc"
	}

	search := c.Query("search")

	var links []*Link
	var err error

	if search == "" && sort == "" {
		links, err = h.linkUsecase.FindAllLinksByUserId(userId, sort)
		if err != nil {
			// 500 Internal Server Error
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
	} else {
		links, err = h.linkUsecase.FindAllLinksByUserIdAndSearch(userId, search, sort, order)
		if err != nil {
			// 500 Internal Server Error
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
	}

	// 200 OK
	c.JSON(http.StatusOK, links)
}

// GetLinkByLinkId godoc
// @Tags 링크
// @Summary 링크를 조회합니다.
// @Description 링크 아이디를 통해 해당 링크를 조회합니다.
// @Accept  json
// @Produce  json
// @Security ApiKeyAuth
// @Param linkId path string true "링크 아이디"
// @Success 200 {object} Link "링크 아이디 기반으로 링크를 반환합니다."
// @Failure 401 {object} util.APIError "Authorization 헤더가 없을 때 반환합니다."
// @Failure 404 {object} util.APIError "링크 아이디에 해당하는 링크가 없을 때 반환합니다."
// @Router /links/{linkId} [get]
func (h LinkHandler) GetLinkByLinkId(c *gin.Context) {
	linkId := c.Param("linkId")

	link, err := h.linkUsecase.FindOneLinkByLinkId(linkId)
	if err != nil {
		// 404 Not Found
		c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
		return
	}

	// 200 OK
	c.JSON(http.StatusOK, link)
}

// GetLinksByLinkBookId godoc
// @Tags 링크
// @Summary 링크를 조회합니다.
// @Description 링크북 아이디를 통해 해당 링크북의 모든 링크를 조회합니다.
// @Accept  json
// @Produce  json
// @Security ApiKeyAuth
// @Param linkBookId path string true "링크북 아이디"
// @Param sort query string false "정렬 기준" Enums(created_at,updated_at,title)
// @Param order query string false "정렬 순서" Enums(asc,desc)
// @Success 200 {object} Link "링크북 아이디 기반으로 링크를 반환합니다."
// @Failure 401 {object} util.APIError "Authorization 헤더가 없을 때 반환합니다."
// @Failure 404 {object} util.APIError "링크북 아이디에 해당하는 링크북이 없을 때 반환합니다."
// @Router /link-books/{linkBookId}/links [get]
func (h LinkHandler) GetLinksByLinkBookId(c *gin.Context) {

	currentUser, exists := c.Get("user")
	if !exists {
		// 401 Unauthorized
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Missing Authorization header"})
		return
	}

	userId := currentUser.(*user.User).UserId

	linkBookId := c.Param("linkBookId")

	sort := c.Query("sort")
	order := c.Query("order")

	if sort == "" {
		sort = "created_at"
	}

	if order == "" {
		order = "asc"
	}

	search := c.Query("search")

	var links []*Link
	var err error

	if search == "" && sort == "" {
		links, err = h.linkUsecase.FindAllLinksByUserIdAndLinkBookId(userId, linkBookId)
		if err != nil {
			// 500 Internal Server Error
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
	} else {
		links, err = h.linkUsecase.FindAllLinksByUserIdAndLinkBookIdAndSearch(userId, linkBookId, search, sort, order)
		if err != nil {
			// 500 Internal Server Error
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
	}

	// 200 OK
	c.JSON(http.StatusOK, links)
}

// DeleteLinkByLinkId godoc
// @Tags 링크
// @Summary 링크를 삭제합니다.
// @Description 링크 아이디를 통해 해당 링크를 삭제합니다.
// @Accept  json
// @Produce  json
// @Security ApiKeyAuth
// @Param linkId path string true "링크 아이디"
// @Success 204 "링크 아이디 기반으로 링크를 삭제합니다."
// @Failure 401 {object} util.APIError "Authorization 헤더가 없을 때 반환합니다."
// @Failure 404 {object} util.APIError "링크 아이디에 해당하는 링크가 없을 때 반환합니다."
// @Router /links/{linkId} [delete]
func (h LinkHandler) DeleteLinkByLinkId(c *gin.Context) {
	linkId := c.Param("linkId")

	err := h.linkUsecase.DeleteOneByLinkId(linkId)
	if err != nil {
		// 404 Not Found
		c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
		return
	}

	// 204 No Content
	c.Status(http.StatusNoContent)
}

// DeleteLinksByUserId godoc
// @Tags 링크
// @Summary 링크를 삭제합니다.
// @Description 사용자 아이디를 통해 해당 사용자의 모든 링크를 삭제합니다.
// @Accept  json
// @Produce  json
// @Security ApiKeyAuth
// @Success 204 "나의 유저아이디 기반으로 모든 링크를 삭제합니다."
// @Failure 401 {object} util.APIError "Authorization 헤더가 없을 때 반환합니다."
// @Router /links [delete]
func (h LinkHandler) DeleteLinksByUserId(c *gin.Context) {
	currentUser, exists := c.Get("user")
	if !exists {
		// 401 Unauthorized
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Missing Authorization header"})
		return
	}

	userId := currentUser.(*user.User).UserId

	err := h.linkUsecase.DeleteAllLinksByUserId(userId)
	if err != nil {
		// 500 Internal Server Error
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	// 204 No Content
	c.Status(http.StatusNoContent)
}

// DeleteLinksByLinkBookId godoc
// @Tags 링크
// @Summary 링크를 삭제합니다.
// @Description 링크북 아이디를 통해 해당 링크북의 모든 링크를 삭제합니다.
// @Accept  json
// @Produce  json
// @Security ApiKeyAuth
// @Param linkBookId path string true "링크북 아이디"
// @Success 204 "링크북 아이디 기반으로 링크를 삭제합니다."
// @Failure 401 {object} util.APIError "Authorization 헤더가 없을 때 반환합니다."
// @Failure 404 {object} util.APIError "링크북 아이디에 해당하는 링크북이 없을 때 반환합니다."
// @Router /link-books/{linkBookId}/links [delete]
func (h LinkHandler) DeleteLinksByLinkBookId(c *gin.Context) {
	currentUser, exists := c.Get("user")
	if !exists {
		// 401 Unauthorized
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Missing Authorization header"})
		return
	}

	userId := currentUser.(*user.User).UserId

	linkBookId := c.Param("linkBookId")

	err := h.linkUsecase.DeleteAllLinksByLinkBookId(userId, linkBookId)
	if err != nil {
		// 404 Not Found
		c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
		return
	}

	// 204 No Content
	c.Status(http.StatusNoContent)
}

// UpdateReadCount godoc
// @Tags 링크
// @Summary 링크의 조횟수를 업데이트 합니다.
// @Description 링크 아이디를 통해 해당 링크의 조횟수를 업데이트 합니다.
// @Accept  json
// @Produce  json
// @Security ApiKeyAuth
// @Param linkId path string true "링크 아이디"
// @Success 204 "링크 아이디 기반으로 링크의 조횟수를 업데이트 합니다."
// @Failure 401 {object} util.APIError "Authorization 헤더가 없을 때 반환합니다."
// @Failure 404 {object} util.APIError "링크 아이디에 해당하는 링크가 없을 때 반환합니다."
// @Router /links/{linkId}/read-count [put]
func (h LinkHandler) UpdateReadCount(c *gin.Context) {
	linkId := c.Param("linkId")

	err := h.linkUsecase.UpdateReadByLinkId(linkId)
	if err != nil {
		// 404 Not Found
		c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
		return
	}

	// 204 No Content
	c.Status(http.StatusNoContent)
}

// UpdateLinkBookIdByLinkId godoc
// @Tags 링크
// @Summary 링크의 링크북 아이디를 업데이트 합니다.
// @Description 링크 아이디를 통해 해당 링크의 링크북 아이디를 업데이트 합니다.
// @Accept  json
// @Produce  json
// @Security ApiKeyAuth
// @Param linkId path string true "링크 아이디"
// @Param linkBookId path string true "링크북 아이디"
// @Success 204 "링크 아이디 기반으로 링크의 링크북 아이디를 업데이트 합니다."
// @Failure 401 {object} util.APIError "Authorization 헤더가 없을 때 반환합니다."
// @Failure 404 {object} util.APIError "링크 아이디에 해당하는 링크가 없을 때 반환합니다."
// @Failure 404 {object} util.APIError "링크북 아이디에 해당하는 링크북이 없을 때 반환합니다."
// @Router /links/{linkId}/link-book-id/{linkBookId} [put]
func (h LinkHandler) UpdateLinkBookIdByLinkId(c *gin.Context) {
	linkId := c.Param("linkId")
	linkBookId := c.Param("linkBookId")

	err := h.linkUsecase.UpdateLinkBookIdByLinkId(linkId, linkBookId)
	if err != nil {
		// 404 Not Found
		c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
		return
	}

	// 204 No Content
	c.Status(http.StatusNoContent)
}

// UpdateTitleAndUrlByLinkId godoc
// @Tags 링크
// @Summary 링크의 타이틀과 URL을 업데이트 합니다.
// @Description 링크 아이디를 통해 해당 링크의 타이틀과 URL을 업데이트 합니다.
// @Accept  json
// @Produce  json
// @Security ApiKeyAuth
// @Param linkId path string true "링크 아이디"
// @Param request body UpdateLinkReq true "태그 생성 요청 본문"
// @Success 200 {object} Link "링크 업데이트가 성공적으로 이루어졌을 때 새로 생성된 링크 객체 반환"
// @Failure 400 {object} util.APIError "요청 본문이 유효하지 않을 때 반환합니다."
// @Failure 401 {object} util.APIError "Authorization 헤더가 없을 때 반환합니다."
// @Failure 404 {object} util.APIError "링크 아이디에 해당하는 링크가 없을 때 반환합니다."
// @Router /links/{linkId} [put]
func (h LinkHandler) UpdateTitleAndUrlByLinkId(c *gin.Context) {
	linkId := c.Param("linkId")

	var req UpdateLinkReq
	if err := c.ShouldBindJSON(&req); err != nil {
		// 400 Bad Request
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request body"})
		return
	}

	link, err := h.linkUsecase.UpdateTitleAndUrlByLinkId(linkId, req.URL, req.Title, req.ThumbnailURL, req.Tags)
	if err != nil {
		// 404 Not Found
		c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, link)
}

// GetThumnailURL godoc
// @Tags 링크
// @Summary 링크의 썸네일 URL과 Title을 가져옵니다.
// @Description 링크의 URL을 통해 해당 링크의 썸네일 URL과 Title을 가져옵니다.
// @Accept  json
// @Produce  json
// @Security ApiKeyAuth
// @Param request body LinkThumbnailReq true "링크 썸네일 요청 본문"
// @Success 200 {object} LinkThumbnailRes "링크 썸네일 URL과 Title을 반환합니다."
// @Failure 400 {object} util.APIError "요청 본문이 유효하지 않을 때 반환합니다."
func (h LinkHandler) GetThumnailURL(c *gin.Context) {
	var req LinkThumbnailReq
	if err := c.ShouldBindJSON(&req); err != nil {
		// 400 Bad Request
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request body"})
		return
	}

	linkThumbnailRes, err := h.linkUsecase.GetThumnailURL(req.URL)
	if err != nil {
		// 500 Internal Server Error
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, linkThumbnailRes)
}
