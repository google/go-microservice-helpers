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

package tracing

import (
	"flag"
	"fmt"

	opentracing "github.com/opentracing/opentracing-go"
	zipkin "github.com/openzipkin/zipkin-go-opentracing"
)

var (
	zipkinURL = flag.String("zipkin-url", "http://localhost:9411/api/v1/spans", "zipkin url for distributed tracing")
)

// InitTracer sets up opentracing via Zipkin.
func InitTracer(hostPort string, serviceName string) error {
	if *zipkinURL == "" {
		return nil
	}

	collector, err := zipkin.NewHTTPCollector(*zipkinURL)
	if err != nil {
		return fmt.Errorf("unable to create Zipkin HTTP collector: %v", err)
	}
	recorder := zipkin.NewRecorder(collector, false, hostPort, serviceName)
	tracer, err := zipkin.NewTracer(
		recorder,
		zipkin.ClientServerSameSpan(false),
		zipkin.TraceID128Bit(true),
	)
	if err != nil {
		return fmt.Errorf("unable to create Zipkin tracer: %v", err)
	}
	opentracing.InitGlobalTracer(tracer)

	return nil
}
