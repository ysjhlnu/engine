package model

import (
	"time"
)

// Gb28181Capture gb28181 2022 抓图
type Gb28181Capture struct {
	ID         uint      `gorm:"autoIncrement:true;primaryKey;column:id;type:int unsigned;not null" json:"id"`
	DeviceID   string    `gorm:"column:device_id;type:varchar(255);default:null;comment:'设备ID'" json:"device_id"`   // 设备ID
	ChannelID  string    `gorm:"column:channel_id;type:varchar(255);default:null;comment:'通道ID'" json:"channel_id"` // 通道ID
	SessionID  string    `gorm:"column:session_id;type:varchar(255);default:null;comment:'会话ID'" json:"session_id"` // 会话ID
	ImgPath    string    `gorm:"column:img_path;type:varchar(255);default:null;comment:'图片路径'" json:"img_path"`     // 图片路径
	Index      uint      `gorm:"column:index;type:int unsigned;default:null;default:0;comment:'张数序号'" json:"index"` // 张数序号
	UploadTime time.Time `gorm:"column:upload_time;type:datetime;default:null;comment:'采集时间'" json:"upload_time"`   // 采集时间
	CreatedAt  time.Time `gorm:"column:created_at;type:datetime;default:null" json:"created_at"`
	UpdatedAt  time.Time `gorm:"column:updated_at;type:datetime;default:null" json:"updated_at"`
}

// TableName get sql table name.获取数据库表名
func (m *Gb28181Capture) TableName() string {
	return "gb28181_capture"
}

// Gb28181CaptureColumns get sql column name.获取数据库列名
var Gb28181CaptureColumns = struct {
	ID         string
	DeviceID   string
	ChannelID  string
	SessionID  string
	ImgPath    string
	Index      string
	UploadTime string
	CreatedAt  string
	UpdatedAt  string
}{
	ID:         "id",
	DeviceID:   "device_id",
	ChannelID:  "channel_id",
	SessionID:  "session_id",
	ImgPath:    "img_path",
	Index:      "index",
	UploadTime: "upload_time",
	CreatedAt:  "created_at",
	UpdatedAt:  "updated_at",
}

// Gb28181Device [...]
type Gb28181Device struct {
	ID                               uint64    `gorm:"autoIncrement:true;primaryKey;unique;column:id;type:bigint unsigned;not null" json:"id"`
	Version                          string    `gorm:"uniqueIndex:uk_device_device;column:version;type:varchar(255);default:null;comment:'国标版本'" json:"version"` // 国标版本
	CustomName                       string    `gorm:"column:custom_name;type:varchar(255);default:null" json:"custom_name"`
	DeviceID                         string    `gorm:"uniqueIndex:uk_device_device;column:device_id;type:varchar(50);not null;comment:'国标ID'" json:"device_id"` // 国标ID
	Name                             string    `gorm:"column:name;type:varchar(255);default:null" json:"name"`
	Manufacturer                     string    `gorm:"column:manufacturer;type:varchar(255);default:null" json:"manufacturer"`
	Model                            string    `gorm:"column:model;type:varchar(255);default:null" json:"model"`
	OnLine                           bool      `gorm:"column:on_line;type:tinyint(1);default:null;default:0" json:"on_line"`
	RegisterTime                     time.Time `gorm:"column:register_time;type:datetime;default:null;comment:'注册时间'" json:"register_time"` // 注册时间
	Status                           string    `gorm:"column:status;type:varchar(255);default:null" json:"status"`
	KeepaliveTime                    time.Time `gorm:"column:keepalive_time;type:datetime;default:null" json:"keepalive_time"`
	IP                               string    `gorm:"column:ip;type:varchar(50);default:null" json:"ip"`
	StreamMode                       string    `gorm:"column:stream_mode;type:varchar(50);default:null" json:"stream_mode"`
	Port                             int       `gorm:"column:port;type:int;default:null" json:"port"`
	Expires                          int       `gorm:"column:expires;type:int;default:null" json:"expires"`
	SubscribeCycleForCatalog         int       `gorm:"column:subscribe_cycle_for_catalog;type:int;default:null;default:0" json:"subscribe_cycle_for_catalog"`
	Firmware                         string    `gorm:"column:firmware;type:varchar(255);default:null" json:"firmware"`
	Transport                        string    `gorm:"column:transport;type:varchar(50);default:null" json:"transport"`
	SubscribeCycleForMobilePosition  int       `gorm:"column:subscribe_cycle_for_mobile_position;type:int;default:null;default:0" json:"subscribe_cycle_for_mobile_position"`
	MobilePositionSubmissionInterval int       `gorm:"column:mobile_position_submission_interval;type:int;default:null;default:5" json:"mobile_position_submission_interval"`
	SubscribeCycleForAlarm           int       `gorm:"column:subscribe_cycle_for_alarm;type:int;default:null;default:0" json:"subscribe_cycle_for_alarm"`
	HostAddress                      string    `gorm:"column:host_address;type:varchar(50);default:null" json:"host_address"`
	Charset                          string    `gorm:"column:charset;type:varchar(50);default:null" json:"charset"`
	SsrcCheck                        bool      `gorm:"column:ssrc_check;type:tinyint(1);default:null;default:0" json:"ssrc_check"`
	GeoCoordSys                      string    `gorm:"column:geo_coord_sys;type:varchar(50);default:null" json:"geo_coord_sys"`
	MediaServerID                    string    `gorm:"column:media_server_id;type:varchar(50);default:null" json:"media_server_id"`
	SdpIP                            string    `gorm:"column:sdp_ip;type:varchar(50);default:null" json:"sdp_ip"`
	LocalIP                          string    `gorm:"column:local_ip;type:varchar(50);default:null" json:"local_ip"`
	Password                         string    `gorm:"column:password;type:varchar(255);default:null" json:"password"`
	AsMessageChannel                 bool      `gorm:"column:as_message_channel;type:tinyint(1);default:null;default:0" json:"as_message_channel"`
	KeepaliveIntervalTime            int       `gorm:"column:keepalive_interval_time;type:int;default:null" json:"keepalive_interval_time"`
	SwitchPrimarySubStream           bool      `gorm:"column:switch_primary_sub_stream;type:tinyint(1);default:null;default:0" json:"switch_primary_sub_stream"`
	BroadcastPushAfterAck            bool      `gorm:"column:broadcast_push_after_ack;type:tinyint(1);default:null;default:0" json:"broadcast_push_after_ack"`
	CreatedAt                        time.Time `gorm:"column:created_at;type:datetime;default:null" json:"created_at"`
	UpdatedAt                        time.Time `gorm:"column:updated_at;type:datetime;default:null" json:"updated_at"`
}

// TableName get sql table name.获取数据库表名
func (m *Gb28181Device) TableName() string {
	return "gb28181_device"
}

// Gb28181DeviceColumns get sql column name.获取数据库列名
var Gb28181DeviceColumns = struct {
	ID                               string
	Version                          string
	CustomName                       string
	DeviceID                         string
	Name                             string
	Manufacturer                     string
	Model                            string
	OnLine                           string
	RegisterTime                     string
	Status                           string
	KeepaliveTime                    string
	IP                               string
	StreamMode                       string
	Port                             string
	Expires                          string
	SubscribeCycleForCatalog         string
	Firmware                         string
	Transport                        string
	SubscribeCycleForMobilePosition  string
	MobilePositionSubmissionInterval string
	SubscribeCycleForAlarm           string
	HostAddress                      string
	Charset                          string
	SsrcCheck                        string
	GeoCoordSys                      string
	MediaServerID                    string
	SdpIP                            string
	LocalIP                          string
	Password                         string
	AsMessageChannel                 string
	KeepaliveIntervalTime            string
	SwitchPrimarySubStream           string
	BroadcastPushAfterAck            string
	CreatedAt                        string
	UpdatedAt                        string
}{
	ID:                               "id",
	Version:                          "version",
	CustomName:                       "custom_name",
	DeviceID:                         "device_id",
	Name:                             "name",
	Manufacturer:                     "manufacturer",
	Model:                            "model",
	OnLine:                           "on_line",
	RegisterTime:                     "register_time",
	Status:                           "status",
	KeepaliveTime:                    "keepalive_time",
	IP:                               "ip",
	StreamMode:                       "stream_mode",
	Port:                             "port",
	Expires:                          "expires",
	SubscribeCycleForCatalog:         "subscribe_cycle_for_catalog",
	Firmware:                         "firmware",
	Transport:                        "transport",
	SubscribeCycleForMobilePosition:  "subscribe_cycle_for_mobile_position",
	MobilePositionSubmissionInterval: "mobile_position_submission_interval",
	SubscribeCycleForAlarm:           "subscribe_cycle_for_alarm",
	HostAddress:                      "host_address",
	Charset:                          "charset",
	SsrcCheck:                        "ssrc_check",
	GeoCoordSys:                      "geo_coord_sys",
	MediaServerID:                    "media_server_id",
	SdpIP:                            "sdp_ip",
	LocalIP:                          "local_ip",
	Password:                         "password",
	AsMessageChannel:                 "as_message_channel",
	KeepaliveIntervalTime:            "keepalive_interval_time",
	SwitchPrimarySubStream:           "switch_primary_sub_stream",
	BroadcastPushAfterAck:            "broadcast_push_after_ack",
	CreatedAt:                        "created_at",
	UpdatedAt:                        "updated_at",
}

// Gb28181DeviceChannel [...]
type Gb28181DeviceChannel struct {
	ID          uint64 `gorm:"autoIncrement:true;primaryKey;unique;column:id;type:bigint unsigned;not null" json:"id"`
	Version     string `gorm:"uniqueIndex:device_channel_unique_device_channel;column:version;type:varchar(255);default:null;comment:'国标版本'" json:"version"` // 国标版本
	DeviceID    string `gorm:"uniqueIndex:device_channel_unique_device_channel;column:device_id;type:varchar(50);not null" json:"device_id"`
	ChannelID   string `gorm:"uniqueIndex:device_channel_unique_device_channel;column:channel_id;type:varchar(50);not null" json:"channel_id"`
	Name        string `gorm:"column:name;type:varchar(255);default:null" json:"name"`
	CustomName  string `gorm:"column:custom_name;type:varchar(255);default:null" json:"custom_name"`
	Manufacture string `gorm:"column:manufacture;type:varchar(50);default:null" json:"manufacture"`
	Model       string `gorm:"column:model;type:varchar(50);default:null" json:"model"`
	Owner       string `gorm:"column:owner;type:varchar(50);default:null;comment:'当为设备时，设备归属'" json:"owner"`            // 当为设备时，设备归属
	CivilCode   string `gorm:"column:civil_code;type:varchar(50);default:null;comment:'行政区域编码'" json:"civil_code"`      // 行政区域编码
	Status      string `gorm:"column:status;type:varchar(255);default:null;default:0;comment:'设备状态（必选）'" json:"status"` // 设备状态（必选）
	Block       string `gorm:"column:block;type:varchar(50);default:null" json:"block"`
	Address     string `gorm:"column:address;type:varchar(50);default:null;comment:'当为设备时，安装地址'" json:"address"`                      // 当为设备时，安装地址
	ParentID    string `gorm:"column:parent_id;type:varchar(50);default:null;comment:'父设备/区域/系统 ID（ 可必选，有父设备需要填写）'" json:"parent_id"` // 父设备/区域/系统 ID（ 可必选，有父设备需要填写）
	SafetyWay   int    `gorm:"column:safety_way;type:int;default:null;comment:'信令安全模式（可选）缺省为 0； 0：不采用； 2： S/MIME 签名方式； 3：S/MIME
加密签名同时采用方式； 4：数字摘要方式'" json:"safety_way"` // 信令安全模式（可选）缺省为 0； 0：不采用； 2： S/MIME 签名方式； 3：S/MIME,加密签名同时采用方式； 4：数字摘要方式
	RegisterWay int `gorm:"column:register_way;type:int;default:null;comment:'注册方式（必选）缺省为 1； 1： 符合 sip3261 标准的认证注册模式； 2：基于口令
的双向认证注册模式； 3： 基于数字证书的双向认证注册模式'" json:"register_way"` // 注册方式（必选）缺省为 1； 1： 符合 sip3261 标准的认证注册模式； 2：基于口令,的双向认证注册模式； 3： 基于数字证书的双向认证注册模式
	CertNum     string `gorm:"column:cert_num;type:varchar(50);default:null;comment:'证书序列号（有证书的设备必选）'" json:"cert_num"`                       // 证书序列号（有证书的设备必选）
	Certifiable int    `gorm:"column:certifiable;type:int;default:null;comment:'证书有效标识（有证书的设备必选）缺省为 0；证书有效标识： 0：无效 1：有效'" json:"certifiable"` // 证书有效标识（有证书的设备必选）缺省为 0；证书有效标识： 0：无效 1：有效
	ErrCode     int    `gorm:"column:err_code;type:int;default:null;comment:'无效原因码（有证书切且证书无效的设备必选）'" json:"err_code"`                         // 无效原因码（有证书切且证书无效的设备必选）
	EndTime     string `gorm:"column:end_time;type:varchar(50);default:null;comment:'证书终止有效期（有证书的设备必选）'" json:"end_time"`                     // 证书终止有效期（有证书的设备必选）
	Secrecy     int    `gorm:"column:secrecy;type:int;default:null;comment:'保密属性（必选）缺省为 0； 0：不涉密， 1：涉密'" json:"secrecy"`                      // 保密属性（必选）缺省为 0； 0：不涉密， 1：涉密
	IPAddress   string `gorm:"column:ip_address;type:varchar(50);default:null;comment:'设备/区域/系统 IP 地址（可选）'" json:"ip_address"`                // 设备/区域/系统 IP 地址（可选）
	Port        int    `gorm:"column:port;type:int;default:null;comment:'设备/区域/系统端口（可选）'" json:"port"`                                        // 设备/区域/系统端口（可选）
	Password    string `gorm:"column:password;type:varchar(255);default:null;comment:'设备口令（可选）'" json:"password"`                             // 设备口令（可选）
	PtzType     int    `gorm:"column:ptz_type;type:int;default:null;comment:'摄像机类型扩展，标识摄像机类型： 1-球机； 2-半球； 3-固定枪机；4-遥控枪机。当
目录项为摄像机时可选'" json:"ptz_type"` // 摄像机类型扩展，标识摄像机类型： 1-球机； 2-半球； 3-固定枪机；4-遥控枪机。当,目录项为摄像机时可选
	CustomPtzType   int       `gorm:"column:custom_ptz_type;type:int;default:null" json:"custom_ptz_type"`
	Longitude       float64   `gorm:"column:longitude;type:double;default:null;comment:'经度（可选）'" json:"longitude"` // 经度（可选）
	CustomLongitude float64   `gorm:"column:custom_longitude;type:double;default:null" json:"custom_longitude"`
	Latitude        float64   `gorm:"column:latitude;type:double;default:null;comment:'纬度（可选）'" json:"latitude"` // 纬度（可选）
	CustomLatitude  float64   `gorm:"column:custom_latitude;type:double;default:null" json:"custom_latitude"`
	StreamID        string    `gorm:"column:stream_id;type:varchar(255);default:null" json:"stream_id"`
	Parental        int       `gorm:"column:parental;type:int;default:null;comment:'当为设备时，是否有子设备（必选） 1 有， 0 没有'" json:"parental"` // 当为设备时，是否有子设备（必选） 1 有， 0 没有
	HasAudio        bool      `gorm:"column:has_audio;type:tinyint(1);default:null;default:0" json:"has_audio"`
	SubCount        int       `gorm:"column:sub_count;type:int;default:null" json:"sub_count"`
	LongitudeGcj02  float64   `gorm:"column:longitude_gcj02;type:double;default:null" json:"longitude_gcj02"`
	LatitudeGcj02   float64   `gorm:"column:latitude_gcj02;type:double;default:null" json:"latitude_gcj02"`
	LongitudeWgs84  float64   `gorm:"column:longitude_wgs84;type:double;default:null" json:"longitude_wgs84"`
	LatitudeWgs84   float64   `gorm:"column:latitude_wgs84;type:double;default:null" json:"latitude_wgs84"`
	BusinessGroupID string    `gorm:"column:business_group_id;type:varchar(50);default:null" json:"business_group_id"`
	GpsTime         time.Time `gorm:"column:gps_time;type:datetime;default:null" json:"gps_time"`
	CreateTime      time.Time `gorm:"column:create_time;type:datetime;not null" json:"create_time"`
	UpdateTime      time.Time `gorm:"column:update_time;type:datetime;not null" json:"update_time"`
}

// TableName get sql table name.获取数据库表名
func (m *Gb28181DeviceChannel) TableName() string {
	return "gb28181_device_channel"
}

// Gb28181DeviceChannelColumns get sql column name.获取数据库列名
var Gb28181DeviceChannelColumns = struct {
	ID              string
	Version         string
	DeviceID        string
	ChannelID       string
	Name            string
	CustomName      string
	Manufacture     string
	Model           string
	Owner           string
	CivilCode       string
	Status          string
	Block           string
	Address         string
	ParentID        string
	SafetyWay       string
	RegisterWay     string
	CertNum         string
	Certifiable     string
	ErrCode         string
	EndTime         string
	Secrecy         string
	IPAddress       string
	Port            string
	Password        string
	PtzType         string
	CustomPtzType   string
	Longitude       string
	CustomLongitude string
	Latitude        string
	CustomLatitude  string
	StreamID        string
	Parental        string
	HasAudio        string
	SubCount        string
	LongitudeGcj02  string
	LatitudeGcj02   string
	LongitudeWgs84  string
	LatitudeWgs84   string
	BusinessGroupID string
	GpsTime         string
	CreateTime      string
	UpdateTime      string
}{
	ID:              "id",
	Version:         "version",
	DeviceID:        "device_id",
	ChannelID:       "channel_id",
	Name:            "name",
	CustomName:      "custom_name",
	Manufacture:     "manufacture",
	Model:           "model",
	Owner:           "owner",
	CivilCode:       "civil_code",
	Status:          "status",
	Block:           "block",
	Address:         "address",
	ParentID:        "parent_id",
	SafetyWay:       "safety_way",
	RegisterWay:     "register_way",
	CertNum:         "cert_num",
	Certifiable:     "certifiable",
	ErrCode:         "err_code",
	EndTime:         "end_time",
	Secrecy:         "secrecy",
	IPAddress:       "ip_address",
	Port:            "port",
	Password:        "password",
	PtzType:         "ptz_type",
	CustomPtzType:   "custom_ptz_type",
	Longitude:       "longitude",
	CustomLongitude: "custom_longitude",
	Latitude:        "latitude",
	CustomLatitude:  "custom_latitude",
	StreamID:        "stream_id",
	Parental:        "parental",
	HasAudio:        "has_audio",
	SubCount:        "sub_count",
	LongitudeGcj02:  "longitude_gcj02",
	LatitudeGcj02:   "latitude_gcj02",
	LongitudeWgs84:  "longitude_wgs84",
	LatitudeWgs84:   "latitude_wgs84",
	BusinessGroupID: "business_group_id",
	GpsTime:         "gps_time",
	CreateTime:      "create_time",
	UpdateTime:      "update_time",
}

// User 用户
type User struct {
	ID         int       `gorm:"autoIncrement:true;primaryKey;column:id;type:int;not null" json:"id"`
	Name       string    `gorm:"unique;column:name;type:varchar(128);not null;comment:'账号'" json:"name"`                                    // 账号
	SystemName string    `gorm:"column:system_name;type:varchar(128);not null;default:智慧电网管理平台;comment:'系统名称'" json:"system_name"`          // 系统名称
	NickName   string    `gorm:"column:nick_name;type:varchar(128);not null;comment:'姓名'" json:"nick_name"`                                 // 姓名
	Phone      string    `gorm:"column:phone;type:varchar(30);default:null;comment:'电话号码'" json:"phone"`                                    // 电话号码
	Email      string    `gorm:"column:email;type:varchar(50);default:null;comment:'邮箱'" json:"email"`                                      // 邮箱
	Pwd        string    `gorm:"column:pwd;type:char(60);default:null;comment:'密码'" json:"pwd"`                                             // 密码
	Token      string    `gorm:"column:token;type:char(32);not null;default:'';comment:'认证码'" json:"token"`                                 // 认证码
	Openid     string    `gorm:"column:openid;type:char(32);default:null;comment:'统一认证平台id'" json:"openid"`                                 // 统一认证平台id
	Oname      string    `gorm:"column:oname;type:varchar(45);default:null;comment:'统一认证平台昵称'" json:"oname"`                                // 统一认证平台昵称
	Status     uint8     `gorm:"column:status;type:tinyint unsigned;default:null;default:0;comment:'状态 0禁用 1启用'" json:"status"`             // 状态 0禁用 1启用
	LoginTime  time.Time `gorm:"column:login_time;type:datetime;default:null;default:0000-01-01 00:00:00;comment:'登陆时间'" json:"login_time"` // 登陆时间
	CreatedAt  time.Time `gorm:"column:created_at;type:datetime;default:null;default:0000-01-01 00:00:00;comment:'创建时间'" json:"created_at"` // 创建时间
	UpdatedAt  time.Time `gorm:"column:updated_at;type:datetime;default:null;comment:'更新时间'" json:"updated_at"`                             // 更新时间
}

// TableName get sql table name.获取数据库表名
func (m *User) TableName() string {
	return "user"
}

// UserColumns get sql column name.获取数据库列名
var UserColumns = struct {
	ID         string
	Name       string
	SystemName string
	NickName   string
	Phone      string
	Email      string
	Pwd        string
	Token      string
	Openid     string
	Oname      string
	Status     string
	LoginTime  string
	CreatedAt  string
	UpdatedAt  string
}{
	ID:         "id",
	Name:       "name",
	SystemName: "system_name",
	NickName:   "nick_name",
	Phone:      "phone",
	Email:      "email",
	Pwd:        "pwd",
	Token:      "token",
	Openid:     "openid",
	Oname:      "oname",
	Status:     "status",
	LoginTime:  "login_time",
	CreatedAt:  "created_at",
	UpdatedAt:  "updated_at",
}
