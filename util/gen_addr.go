package util

// 生成推流和拉流地址

func GenAddr(streamPath string) map[string]string {
	// 通常，播放地址的规则是 [协议]://[Host][:Port]/[插件名]/[StreamPath]

	addr := make(map[string]string)

	// /hdl/live/test.flv
	addr["http-flv"] = "/hdl/" + streamPath + ".flv"

	// hls协议的地址为 http://localhost:8080/hls/live/test.m3u8
	addr["hls"] = "/hls/" + streamPath + ".m3u8"

	// ws-flv协议的地址为 ws://localhost:8080/jessica/live/test.flv
	addr["ws-flv"] = "/jessica/" + streamPath + ".flv"

	//rtmp播放地址则为 rtmp://localhost/live/test
	addr["rtmp"] = "/" + streamPath

	//rtsp播放地址则为 rtsp://localhost/live/test
	addr["rtsp"] = "/" + streamPath

	// webrtc://localhost/live/test
	addr["webrtc"] = "/" + streamPath
	return addr
}
