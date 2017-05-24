/*

Copyright 2017 Google Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

*/

package server

import (
	"crypto/tls"
	"crypto/x509"
	"flag"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"strings"

	"github.com/golang/glog"
	"google.golang.org/grpc"
)

var (
	// ListenAddress is the grpc listen address
	ListenAddress = flag.String("listen", "", "GRPC listen address")

	serverCert = flag.String("server-cert", "", "server TLS cert")
	serverKey  = flag.String("server-key", "", "server TLS key")
	clientCA   = flag.String("client-ca", "", "client CA")
)

func grpcHandlerFunc(grpcServer *grpc.Server, otherHandler http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// TODO(tamird): point to merged gRPC code rather than a PR.
		// This is a partial recreation of gRPC's internal checks https://github.com/grpc/grpc-go/pull/514/files#diff-95e9a25b738459a2d3030e1e6fa2a718R61
		if r.ProtoMajor == 2 && strings.Contains(r.Header.Get("Content-Type"), "application/grpc") {
			grpcServer.ServeHTTP(w, r)
		} else {
			otherHandler.ServeHTTP(w, r)
		}
	})
}

// ListenAndServe starts grpc server
func ListenAndServe(grpcServer *grpc.Server, otherHandler http.Handler) error {
	lis, err := net.Listen("tcp", *ListenAddress)
	if err != nil {
		return fmt.Errorf("failed to listen: %v", err)
	}

	if *serverCert != "" {
		serverCertKeypair, err := tls.LoadX509KeyPair(*serverCert, *serverKey)
		if err != nil {
			return fmt.Errorf("failed to load server tls cert/key: %v", err)
		}

		var clientCertPool *x509.CertPool
		if *clientCA != "" {
			caCert, err := ioutil.ReadFile(*clientCA)
			if err != nil {
				return fmt.Errorf("failed to load client ca: %v", err)
			}
			clientCertPool = x509.NewCertPool()
			clientCertPool.AppendCertsFromPEM(caCert)
		}

		var h http.Handler
		if otherHandler == nil {
			h = grpcServer
		} else {
			h = grpcHandlerFunc(grpcServer, otherHandler)
		}

		httpsServer := &http.Server{
			Handler: h,
			TLSConfig: &tls.Config{
				Certificates: []tls.Certificate{serverCertKeypair},
				NextProtos:   []string{"h2"},
			},
		}

		if clientCertPool != nil {
			httpsServer.TLSConfig.ClientCAs = clientCertPool
			httpsServer.TLSConfig.ClientAuth = tls.RequireAndVerifyClientCert
		} else {
			glog.Warningf("no client ca provided for grpc server")
		}

		glog.Infof("serving on %v", *ListenAddress)
		err = httpsServer.Serve(tls.NewListener(lis, httpsServer.TLSConfig))
		return fmt.Errorf("failed to serve: %v", err)
	}

	glog.Warningf("serving INSECURE on %v", *ListenAddress)
	err = grpcServer.Serve(lis)
	return fmt.Errorf("failed to serve: %v", err)
}
