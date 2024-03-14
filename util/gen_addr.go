package util

// 生成推流和拉流地址

func GenAddr(host, port, streamPath string) map[string]string {
	// 通常，播放地址的规则是 [协议]://[Host][:Port]/[插件名]/[StreamPath]

	addr := make(map[string]string)

	// /hdl/live/test.flv
	addr["http-flv"] = "http://" + host + port + "/hdl/" + streamPath + ".flv"

	// hls协议的地址为 http://localhost:8080/hls/live/test.m3u8
	addr["hls"] = "http://" + host + port + "/hls/" + streamPath + ".m3u8"

	// ws-flv协议的地址为 ws://localhost:8080/jessica/live/test.flv
	addr["ws-flv"] = "ws://" + host + port + "/jessica/" + streamPath + ".flv"

	//rtmp播放地址则为 rtmp://localhost/live/test
	addr["rtmp"] = "rtmp://" + host + "/" + streamPath

	//rtsp播放地址则为 rtsp://localhost/live/test
	addr["rtsp"] = "rtsp://" + host + "/" + streamPath

	// webrtc://localhost/live/test
	addr["webrtc"] = "webrtc://" + host + port + "/webrtc/play/" + streamPath
	return addr
}
