package k8s_test

import (
	. "github.com/cloudfoundry/uaa/matchers"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"path/filepath"
)

var _ = Describe("Deployment", func() {
	var templates []string

	BeforeEach(func() {
		templates = []string{
			pathToFile("deployment.yml"),
			pathToFile(filepath.Join("values", "_values.yml")),
			pathToFile(filepath.Join("values", "image.yml")),
			pathToFile(filepath.Join("values", "version.yml")),
			pathToFile("deployment.star"),
		}
	})

	It("Renders a deployment for the UAA", func() {
		ctx := NewRenderingContext(templates...)

		Expect(ctx).To(
			ProduceYAML(
				RepresentingDeployment().WithPodMatching(func(pod *PodMatcher) {
					pod.WithServiceAccountMatching("uaa")
					pod.WithContainerMatching(func(container *ContainerMatcher) {
						container.WithName("uaa")
						container.WithImageContaining("cfidentity/uaa@sha256:")
						container.WithEnvVar("spring_profiles", "default,hsqldb")
						container.WithEnvVar("UAA_CONFIG_PATH", "/etc/config")
						container.WithEnvVar("BPL_TOMCAT_ACCESS_LOGGING", "y")
						container.WithEnvVar("JAVA_OPTS", "-Djava.security.egd=file:/dev/./urandom -Dlogging.config=/etc/config/log4j2.properties")
						container.WithResourceRequests("512Mi", "500m")
					})
				}),
			),
		)
	})

	It("Renders a custom image for the UAA", func() {
		ctx := NewRenderingContext(templates...).WithData(
			map[string]string{"image": "image from testing"})

		Expect(ctx).To(
			ProduceYAML(
				RepresentingDeployment().WithPodMatching(func(pod *PodMatcher) {
					pod.WithContainerMatching(func(container *ContainerMatcher) {
						container.WithName("uaa")
						container.WithImage("image from testing")
					})
				}),
			),
		)
	})

	It("Renders custom resource requests for the UAA", func() {
		ctx := NewRenderingContext(templates...).WithData(
			map[string]string{
				"resources.requests.memory": "888Mi",
				"resources.requests.cpu":    "999m",
			})

		Expect(ctx).To(
			ProduceYAML(
				RepresentingDeployment().WithPodMatching(func(pod *PodMatcher) {
					pod.WithContainerMatching(func(container *ContainerMatcher) {
						container.WithName("uaa")
						container.WithResourceRequests("888Mi", "999m")
					})
				}),
			),
		)
	})

	When("provided with custom values", func() {
		var (
			databaseScheme string
			ctx            RenderingContext
		)

		BeforeEach(func() {
			databaseScheme = "postgresql"
			ctx = NewRenderingContext(templates...).WithData(map[string]string{
				"database.scheme": databaseScheme,
			})
		})

		It("Renders a deployment with the custom values interpolated", func() {
			Expect(ctx).To(
				ProduceYAML(
					RepresentingDeployment().WithPodMatching(func(pod *PodMatcher) {
						pod.WithContainerMatching(func(container *ContainerMatcher) {
							container.WithName("uaa")
							container.WithEnvVar("spring_profiles", databaseScheme)
						})
					}),
				),
			)
		})
	})

	It("Renders common labels for the deployment", func() {
		templates = append(templates, pathToFile("metadata.yml"))
		ctx := NewRenderingContext(templates...).WithData(map[string]string{
			"version": "1.0.0",
		})

		labels := map[string]string{
			"app.kubernetes.io/name":       "uaa",
			"app.kubernetes.io/instance":   "uaa-standalone",
			"app.kubernetes.io/version":    "1.0.0",
			"app.kubernetes.io/component":  "authorization_server",
			"app.kubernetes.io/part-of":    "uaa",
			"app.kubernetes.io/managed-by": "kubectl",
		}
		Expect(ctx).To(
			ProduceYAML(RepresentingDeployment().
				WithLabels(labels).
				WithNamespace("default").
				WithPodMatching(func(pod *PodMatcher) {
					pod.WithLabels(labels)
				}),
			),
		)
	})
})
