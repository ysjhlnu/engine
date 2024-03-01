package engine

import (
	"encoding/json"
	"github.com/marspere/goencrypt"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"go.uber.org/zap"
	"gopkg.in/yaml.v3"
	"m7s.live/engine/v4/codec"
	"m7s.live/engine/v4/config"
	"m7s.live/engine/v4/model"
	"m7s.live/engine/v4/util"
)

const (
	NO_SUCH_CONIFG = "no such config"
	NO_SUCH_STREAM = "no such stream"
)

type GlobalConfig struct {
	config.Engine
}

// ServeHTTP 所有API接口
func (conf *GlobalConfig) ServeHTTP(rw http.ResponseWriter, r *http.Request) {
	if r.URL.Path == "/favicon.ico" {
		http.ServeFile(rw, r, "favicon.ico")
		return
	}
	rw.Write([]byte("Monibuca API Server\n"))
	for _, api := range apiList {
		rw.Write([]byte(api + "\n"))
	}
}

func (conf *GlobalConfig) API_summary(rw http.ResponseWriter, r *http.Request) {
	util.ReturnValue(&summary, rw, r)
}

func (conf *GlobalConfig) API_Streams(rw http.ResponseWriter, r *http.Request) {
	util.ReturnValue(&summary.Streams, rw, r)
}

func (conf *GlobalConfig) API_plugins(rw http.ResponseWriter, r *http.Request) {
	util.ReturnValue(Plugins, rw, r)
}

func (conf *GlobalConfig) API_stream(rw http.ResponseWriter, r *http.Request) {
	if streamPath := r.URL.Query().Get("streamPath"); streamPath != "" {
		if s := Streams.Get(streamPath); s != nil {
			util.ReturnValue(s, rw, r)
		} else {
			util.ReturnError(util.APIErrorNoStream, NO_SUCH_STREAM, rw, r)
		}
	} else {
		util.ReturnError(util.APIErrorNoStream, "no streamPath", rw, r)
	}
}

func (conf *GlobalConfig) API_sysInfo(rw http.ResponseWriter, r *http.Request) {
	util.ReturnValue(&SysInfo, rw, r)
}

func (conf *GlobalConfig) API_closeStream(w http.ResponseWriter, r *http.Request) {
	if streamPath := r.URL.Query().Get("streamPath"); streamPath != "" {
		if s := Streams.Get(streamPath); s != nil {
			s.Close()
			util.ReturnOK(w, r)
		} else {
			util.ReturnError(util.APIErrorNoStream, NO_SUCH_STREAM, w, r)
		}
	} else {
		util.ReturnError(util.APIErrorNoStream, "no streamPath", w, r)
	}
}

// API_getConfig 获取指定的配置信息
func (conf *GlobalConfig) API_getConfig(w http.ResponseWriter, r *http.Request) {
	var p *Plugin
	var q = r.URL.Query()
	if configName := q.Get("name"); configName != "" {
		if c, ok := Plugins[configName]; ok {
			p = c
		} else {
			util.ReturnError(util.APIErrorNoConfig, NO_SUCH_CONIFG, w, r)
			return
		}
	} else {
		p = Engine
	}
	var data any
	if q.Get("yaml") != "" {
		var tmp struct {
			File     string
			Modified string
			Merged   string
		}
		mm, err := yaml.Marshal(p.RawConfig.File)
		if err == nil {
			tmp.File = string(mm)
		}
		mm, err = yaml.Marshal(p.RawConfig.Modify)
		if err == nil {
			tmp.Modified = string(mm)
		}
		mm, err = yaml.Marshal(p.RawConfig.GetMap())
		if err == nil {
			tmp.Merged = string(mm)
		}
		data = &tmp
	} else if q.Get("formily") != "" {
		data = p.RawConfig.GetFormily()
	} else {
		data = &p.RawConfig
	}
	util.ReturnValue(data, w, r)
}

// API_modifyConfig 修改并保存配置
func (conf *GlobalConfig) API_modifyConfig(w http.ResponseWriter, r *http.Request) {
	var p *Plugin
	var q = r.URL.Query()
	var err error
	if configName := q.Get("name"); configName != "" {
		if c, ok := Plugins[configName]; ok {
			p = c
		} else {
			util.ReturnError(util.APIErrorNoConfig, NO_SUCH_CONIFG, w, r)
			return
		}
	} else {
		p = Engine
	}
	var modified map[string]any
	if q.Get("yaml") != "" {
		err = yaml.NewDecoder(r.Body).Decode(&modified)
	} else {
		err = json.NewDecoder(r.Body).Decode(&modified)
	}
	if err != nil {
		util.ReturnError(util.APIErrorDecode, err.Error(), w, r)
		return
	}
	p.RawConfig.ParseModifyFile(modified)
	if err = p.Save(); err != nil {
		util.ReturnError(util.APIErrorSave, err.Error(), w, r)
		return
	}
	util.ReturnOK(w, r)
}

// API_updateConfig 热更新配置
func (conf *GlobalConfig) API_updateConfig(w http.ResponseWriter, r *http.Request) {
	var p *Plugin
	var q = r.URL.Query()
	if configName := q.Get("name"); configName != "" {
		if c, ok := Plugins[configName]; ok {
			p = c
		} else {
			util.ReturnError(util.APIErrorNoConfig, NO_SUCH_CONIFG, w, r)
			return
		}
	} else {
		p = Engine
	}
	var err error
	var modified map[string]any
	if q.Get("yaml") != "" {
		err = yaml.NewDecoder(r.Body).Decode(&modified)
	} else {
		err = json.NewDecoder(r.Body).Decode(&modified)
	}
	if err != nil {
		util.ReturnError(util.APIErrorDecode, err.Error(), w, r)
		return
	}
	p.RawConfig.ParseModifyFile(modified)
	if err = p.Save(); err != nil {
		util.ReturnError(util.APIErrorSave, err.Error(), w, r)
		return
	}
	p.Update(&p.RawConfig)
	util.ReturnOK(w, r)
}

func (conf *GlobalConfig) API_list_pull(w http.ResponseWriter, r *http.Request) {
	util.ReturnFetchValue(func() (result []any) {
		Pullers.Range(func(key, value any) bool {
			result = append(result, value)
			return true
		})
		return
	}, w, r)
}

func (conf *GlobalConfig) API_list_push(w http.ResponseWriter, r *http.Request) {
	util.ReturnFetchValue(func() (result []any) {
		Pushers.Range(func(key, value any) bool {
			result = append(result, value)
			return true
		})
		return
	}, w, r)
}

func (conf *GlobalConfig) API_stop_push(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	pusher, ok := Pushers.Load(q.Get("url"))
	if ok {
		pusher.(IPusher).Stop()
		util.ReturnOK(w, r)
	} else {
		util.ReturnError(util.APIErrorNoPusher, "no such pusher", w, r)
	}
}

func (conf *GlobalConfig) API_stop_subscribe(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	streamPath := q.Get("streamPath")
	id := q.Get("id")
	s := Streams.Get(streamPath)
	if s == nil {
		util.ReturnError(util.APIErrorNoStream, NO_SUCH_STREAM, w, r)
		return
	}
	suber := s.Subscribers.Find(id)
	if suber == nil {
		util.ReturnError(util.APIErrorNoSubscriber, "no such subscriber", w, r)
		return
	}
	suber.Stop(zap.String("reason", "stop by api"))
	util.ReturnOK(w, r)
}

func (conf *GlobalConfig) API_replay_rtpdump(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	streamPath := q.Get("streamPath")
	if streamPath == "" {
		streamPath = "dump/rtsp"
	}
	dumpFile := q.Get("dump")
	if dumpFile == "" {
		dumpFile = streamPath + ".rtpdump"
	}
	cv := q.Get("vcodec")
	ca := q.Get("acodec")
	cvp := q.Get("vpayload")
	cap := q.Get("apayload")
	var pub RTPDumpPublisher
	i, _ := strconv.ParseInt(cvp, 10, 64)
	pub.VPayloadType = byte(i)
	i, _ = strconv.ParseInt(cap, 10, 64)
	pub.APayloadType = byte(i)
	switch cv {
	case "h264":
		pub.VCodec = codec.CodecID_H264
	case "h265":
		pub.VCodec = codec.CodecID_H265
	}
	switch ca {
	case "aac":
		pub.ACodec = codec.CodecID_AAC
	case "pcma":
		pub.ACodec = codec.CodecID_PCMA
	case "pcmu":
		pub.ACodec = codec.CodecID_PCMU
	}
	ss := strings.Split(dumpFile, ",")
	if len(ss) > 1 {
		if err := Engine.Publish(streamPath, &pub); err != nil {
			util.ReturnError(util.APIErrorPublish, err.Error(), w, r)
		} else {
			for _, s := range ss {
				f, err := os.Open(s)
				if err != nil {
					util.ReturnError(util.APIErrorOpen, err.Error(), w, r)
					return
				}
				go pub.Feed(f)
			}
			util.ReturnOK(w, r)
		}
	} else {
		f, err := os.Open(dumpFile)
		if err != nil {
			util.ReturnError(util.APIErrorOpen, err.Error(), w, r)
			return
		}
		if err := Engine.Publish(streamPath, &pub); err != nil {
			util.ReturnError(util.APIErrorPublish, err.Error(), w, r)
		} else {
			pub.SetIO(f)
			util.ReturnOK(w, r)
			go pub.Feed(f)
		}
	}
}

func (conf *GlobalConfig) API_replay_ts(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	streamPath := q.Get("streamPath")
	if streamPath == "" {
		streamPath = "dump/ts"
	}
	dumpFile := q.Get("dump")
	if dumpFile == "" {
		dumpFile = streamPath + ".ts"
	}
	f, err := os.Open(dumpFile)
	if err != nil {
		util.ReturnError(util.APIErrorOpen, err.Error(), w, r)
		return
	}
	var pub TSPublisher
	if err := Engine.Publish(streamPath, &pub); err != nil {
		util.ReturnError(util.APIErrorPublish, err.Error(), w, r)
	} else {
		tsReader := NewTSReader(&pub)
		pub.SetIO(f)
		go func() {
			tsReader.Feed(f)
			tsReader.Close()
		}()
		util.ReturnOK(w, r)
	}
}

func (conf *GlobalConfig) API_replay_mp4(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	streamPath := q.Get("streamPath")
	if streamPath == "" {
		streamPath = "dump/mp4"
	}
	dumpFile := q.Get("dump")
	if dumpFile == "" {
		dumpFile = streamPath + ".mp4"
	}
	var pub MP4Publisher
	f, err := os.Open(dumpFile)
	if err != nil {
		util.ReturnError(util.APIErrorOpen, err.Error(), w, r)
		return
	}
	if err := Engine.Publish(streamPath, &pub); err != nil {
		util.ReturnError(util.APIErrorPublish, err.Error(), w, r)
	} else {
		pub.SetIO(f)
		util.ReturnOK(w, r)
		go pub.ReadMP4Data(f)
	}
}

func (conf *GlobalConfig) API_insertSEI(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	streamPath := q.Get("streamPath")
	s := Streams.Get(streamPath)
	if s == nil {
		util.ReturnError(util.APIErrorNoStream, NO_SUCH_STREAM, w, r)
		return
	}
	t := q.Get("type")
	tb, err := strconv.ParseInt(t, 10, 8)
	if err != nil {
		if t == "" {
			tb = 5
		} else {
			util.ReturnError(util.APIErrorQueryParse, "type must a number", w, r)
			return
		}
	}
	sei, err := io.ReadAll(r.Body)
	if err == nil {
		if s.Tracks.AddSEI(byte(tb), sei) {
			util.ReturnOK(w, r)
		} else {
			util.ReturnError(util.APIErrorNoSEI, "no sei track", w, r)
		}
	} else {
		util.ReturnError(util.APIErrorNoBody, err.Error(), w, r)
	}
}

// API_user_login 用户登录
func (conf *GlobalConfig) API_user_login(w http.ResponseWriter, r *http.Request) {

	type userinfo struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}

	raw, err := io.ReadAll(r.Body)
	if err != nil {
		Engine.Error(err.Error())
		util.ReturnError(util.APIErrorInternal, "内部错误", w, r)
		return
	}
	userInfo := userinfo{}
	if err = json.Unmarshal(raw, &userInfo); err != nil {
		Engine.Error(err.Error())
		util.ReturnError(util.APIErrorInternal, "内部错误", w, r)
		return
	}

	if userInfo.Username == "" || userInfo.Password == "" {
		util.ReturnError(util.APIErrorUserEmpty, "用户名密码为空", w, r)
		return
	}

	// 校验用户名和密码是否正确
	dbuser := model.UserLoginData{}
	err = Engine.DB.Model(&model.User{}).Where("binary name = ?", userInfo.Username).First(&dbuser).Error
	if err != nil {
		Engine.Error(err.Error())
		Engine.Logger.Sugar().Debugf("账号或密码有误[%s]-[%s]-状态[%d]", userInfo.Username, userInfo.Password, dbuser.Status)
		util.ReturnError(util.APIErrorUserPwd, "账号或密码有误", w, r)
		return
	}

	if dbuser.Status == 0 {
		Engine.Logger.Sugar().Debugf("用户禁用[%s]-[%s]-状态[%d]", userInfo.Username, userInfo.Password, dbuser.Status)
		util.ReturnError(util.APIErrorUserDeny, "用户禁用", w, r)
		return
	}

	encodeText := "cqset123"
	cipher := goencrypt.NewDESCipher([]byte(encodeText), []byte(""), goencrypt.ECBMode, goencrypt.Pkcs7, goencrypt.PrintBase64)
	cipherText, err := cipher.DESEncrypt([]byte(userInfo.Password))
	if err != nil {
		Engine.Error(err.Error())
		util.ReturnError(util.APIErrorInternal, "内部错误", w, r)
		return
	}
	if cipherText != dbuser.Pwd {
		util.ReturnError(util.APIErrorUserPwdError, "密码错误", w, r)
		return
	}
	tokenString, err := util.GenToken(dbuser.Name, dbuser.ID)
	if err != nil {
		util.ReturnError(util.APIErrorUserTokenInvalid, "无效token", w, r)
		return
	}

	dbuser.LoginTime = time.Now()
	err = Engine.DB.Model(&model.User{}).Where("id = ?", dbuser.ID).Update("login_time", time.Now()).Error
	if err != nil {
		Engine.Error(err.Error())
	}
	util.ReturnValue(map[string]interface{}{"user": userInfo.Username, "time": dbuser.LoginTime.Format(time.DateTime), "token": tokenString}, w, r)
}

func (conf *GlobalConfig) API_user_register(w http.ResponseWriter, r *http.Request) {
	type userinfo struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}

	raw, err := io.ReadAll(r.Body)
	if err != nil {
		Engine.Error(err.Error())
		util.ReturnError(util.APIErrorInternal, "内部错误", w, r)
		return
	}
	userInfo := userinfo{}
	if err = json.Unmarshal(raw, &userInfo); err != nil {
		Engine.Error(err.Error())
		util.ReturnError(util.APIErrorInternal, "内部错误", w, r)
		return
	}

	if userInfo.Username == "" || userInfo.Password == "" {
		util.ReturnError(util.APIErrorUserEmpty, "用户名密码为空", w, r)
		return
	}

	encodeText := "cqset123"
	cipher := goencrypt.NewDESCipher([]byte(encodeText), []byte(""), goencrypt.ECBMode, goencrypt.Pkcs7, goencrypt.PrintBase64)
	password, err := cipher.DESEncrypt([]byte(userInfo.Password))
	if err != nil {
		Engine.Error(err.Error())
		util.ReturnError(util.APIErrorInternal, "内部错误", w, r)
		return
	}

	err = Engine.DB.Create(&model.User{
		Name:       userInfo.Username,
		SystemName: "",
		NickName:   "",
		Phone:      "",
		Email:      "",
		Pwd:        password,
		Token:      "",
		Openid:     "",
		Oname:      "",
		Status:     1,
		CreatedAt:  time.Now(),
		UpdatedAt:  time.Now(),
	}).Error
	if err != nil {
		Engine.Error(err.Error())
		util.ReturnError(util.APIErrorInternal, "内部错误", w, r)
		return
	}
	util.ReturnOK(w, r)
}
