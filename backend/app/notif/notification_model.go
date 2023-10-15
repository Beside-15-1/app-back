package notif

import (
	"context"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"joosum-backend/pkg/db"
	"time"
)

type NotificationModel struct {
}

type Agree struct {
	AgreeId         string `bson:"_id"`
	DeviceId        string `bson:"device_id"`
	IsReadAgree     bool   `bson:"is_read_agree"`
	IsClassifyAgree bool   `bson:"is_classify_agree"`
	UserId          string `bson:"user_id"`
}

type DeviceReq struct {
	DeviceId string `json:"deviceId"`
}

func (NotificationModel) SaveDeviceId(deviceId, userId string) (*mongo.UpdateResult, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	filter := bson.D{{"user_id", userId}}
	update := bson.D{{"$set", bson.D{{"device_id", deviceId}}}}
	opts := options.Update().SetUpsert(true)

	result, err := db.NotificationAgreeCollection.UpdateOne(ctx, filter, update, opts)
	if err != nil {
		return nil, err
	}
	return result, nil
}
