class QualysK8s < Formula
  desc "Agentless Kubernetes security scanner for CIS, NSA-CISA, and MITRE compliance"
  homepage "https://github.com/nelssec/qualys-agentless"
  version "0.1.0"
  license "Apache-2.0"

  on_macos do
    on_arm do
      url "https://github.com/nelssec/qualys-agentless/releases/download/v#{version}/qualys-k8s-darwin-arm64"
      sha256 "PLACEHOLDER_SHA256_DARWIN_ARM64"

      def install
        bin.install "qualys-k8s-darwin-arm64" => "qualys-k8s"
      end
    end

    on_intel do
      url "https://github.com/nelssec/qualys-agentless/releases/download/v#{version}/qualys-k8s-darwin-amd64"
      sha256 "PLACEHOLDER_SHA256_DARWIN_AMD64"

      def install
        bin.install "qualys-k8s-darwin-amd64" => "qualys-k8s"
      end
    end
  end

  on_linux do
    on_arm do
      url "https://github.com/nelssec/qualys-agentless/releases/download/v#{version}/qualys-k8s-linux-arm64"
      sha256 "PLACEHOLDER_SHA256_LINUX_ARM64"

      def install
        bin.install "qualys-k8s-linux-arm64" => "qualys-k8s"
      end
    end

    on_intel do
      url "https://github.com/nelssec/qualys-agentless/releases/download/v#{version}/qualys-k8s-linux-amd64"
      sha256 "PLACEHOLDER_SHA256_LINUX_AMD64"

      def install
        bin.install "qualys-k8s-linux-amd64" => "qualys-k8s"
      end
    end
  end

  test do
    assert_match "qualys-k8s", shell_output("#{bin}/qualys-k8s --version")
  end
end
