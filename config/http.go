package config

import (
	"context"
	"crypto/tls"
	"embed"
	"io/fs"
	"net/http"
	"path"
	"time"

	"github.com/logrusorgru/aurora/v4"
	"golang.org/x/sync/errgroup"
	"m7s.live/engine/v4/log"
	"m7s.live/engine/v4/util"
)

var _ HTTPConfig = (*HTTP)(nil)

type Middleware func(string, http.Handler) http.Handler
type HTTP struct {
	ExternalIp    string        `desc:"外部IP"`
	ListenAddr    string        `desc:"监听地址"`
	ListenAddrTLS string        `desc:"监听地址HTTPS"`
	CertFile      string        `desc:"HTTPS证书文件"`
	KeyFile       string        `desc:"HTTPS密钥文件"`
	CORS          bool          `default:"true" desc:"是否自动添加CORS头"` //是否自动添加CORS头
	UserName      string        `desc:"基本身份认证用户名"`
	Password      string        `desc:"基本身份认证密码"`
	ReadTimeout   time.Duration `desc:"读取超时"`
	WriteTimeout  time.Duration `desc:"写入超时"`
	IdleTimeout   time.Duration `desc:"空闲超时"`
	mux           *http.ServeMux
	middlewares   []Middleware
}
type HTTPConfig interface {
	GetHTTPConfig() *HTTP
	Listen(ctx context.Context) error
	Handle(string, http.Handler)
	Handler(*http.Request) (http.Handler, string)
	AddMiddleware(Middleware)
}

func (config *HTTP) AddMiddleware(middleware Middleware) {
	config.middlewares = append(config.middlewares, middleware)
}

// Handle 没有mux会创建然后把handler添加到自己的路由中去
func (config *HTTP) Handle(path string, f http.Handler) {
	if config.mux == nil {
		config.mux = http.NewServeMux()
	}
	if config.CORS {
		f = util.CORS(f)
	}
	if config.UserName != "" && config.Password != "" {
		//f = util.BasicAuth(config.UserName, config.Password, f)
		f = util.CheckToken(f)
	}
	for _, middleware := range config.middlewares {
		f = middleware(path, f)
	}
	config.mux.Handle(path, f)
}

func (config *HTTP) GetHTTPConfig() *HTTP {
	return config
}

func (config *HTTP) Handler(r *http.Request) (h http.Handler, pattern string) {
	return config.mux.Handler(r)
}

func (config *HTTP) Listen(ctx context.Context) error {

	if config.mux == nil {
		return nil
	}
	var g errgroup.Group
	if config.ListenAddrTLS != "" && (config == &Global.HTTP || config.ListenAddrTLS != Global.ListenAddrTLS) {
		g.Go(func() error {
			if Global.LogLang == "zh" {
				log.Info("🌐 https 监听在 ", aurora.Blink(config.ListenAddrTLS))
			} else {
				log.Info("🌐 https listen at ", aurora.Blink(config.ListenAddrTLS))
			}
			cer, _ := tls.X509KeyPair(LocalCert, LocalKey)
			var server = http.Server{
				Addr:         config.ListenAddrTLS,
				ReadTimeout:  config.ReadTimeout,
				WriteTimeout: config.WriteTimeout,
				IdleTimeout:  config.IdleTimeout,
				Handler:      config.mux,
				TLSConfig: &tls.Config{
					Certificates: []tls.Certificate{cer},
					CipherSuites: []uint16{
						tls.TLS_AES_128_GCM_SHA256,
						tls.TLS_CHACHA20_POLY1305_SHA256,
						tls.TLS_AES_256_GCM_SHA384,
						//tls.TLS_RSA_WITH_AES_128_CBC_SHA,
						//tls.TLS_RSA_WITH_AES_256_CBC_SHA,
						//tls.TLS_RSA_WITH_AES_128_GCM_SHA256,
						//tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
						tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
						tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
						tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
						tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
						tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
						tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
						tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,
						tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
						tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,
						tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
						tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
						tls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
					},
				},
			}
			return server.ListenAndServeTLS(config.CertFile, config.KeyFile)
		})
	}
	if config.ListenAddr != "" && (config == &Global.HTTP || config.ListenAddr != Global.ListenAddr) {
		g.Go(func() error {
			if Global.LogLang == "zh" {
				log.Info("🌐 http 监听在 ", aurora.Blink(config.ListenAddr))
			} else {
				log.Info("🌐 http listen at ", aurora.Blink(config.ListenAddr))
			}
			var server = http.Server{
				Addr:         config.ListenAddr,
				ReadTimeout:  config.ReadTimeout,
				WriteTimeout: config.WriteTimeout,
				IdleTimeout:  config.IdleTimeout,
				Handler:      config.mux,
			}
			//config.mux.Handle("/web/", AssetHandler("/web/", Assets, "./static"))
			return server.ListenAndServe()
		})
	}
	g.Go(func() error {
		<-ctx.Done()
		return ctx.Err()
	})
	return g.Wait()
}

type fsFunc func(name string) (fs.File, error)

func (f fsFunc) Open(name string) (fs.File, error) {
	return f(name)
}

// AssetHandler returns an http.Handler that will serve files from
// the Assets embed.FS. When locating a file, it will strip the given
// prefix from the request and prepend the root to the filesystem.
func AssetHandler(prefix string, assets embed.FS, root string) http.Handler {
	handler := fsFunc(func(name string) (fs.File, error) {
		assetPath := path.Join(root, name)

		// If we can't find the asset, fs can handle the error
		file, err := assets.Open(assetPath)
		if err != nil {
			return nil, err
		}

		// Otherwise assume this is a legitimate request routed correctly
		return file, err
	})

	return http.StripPrefix(prefix, http.FileServer(http.FS(handler)))
}
