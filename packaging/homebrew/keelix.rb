# Homebrew formula template for Keelix.
# Publish to a tap (e.g. jwlamon/homebrew-keelix) and fill in the
# release URLs + sha256 sums for each tagged release.
class Keelix < Formula
  desc "Pre-deployment security gate for self-hosted Docker stacks"
  homepage "https://github.com/jwlamon/keelix"
  version "0.1.0"
  license "Apache-2.0"

  on_macos do
    on_arm do
      url "https://github.com/jwlamon/keelix/releases/download/v#{version}/keelix-darwin-arm64"
      sha256 "REPLACE_WITH_SHA256"
    end
    on_intel do
      url "https://github.com/jwlamon/keelix/releases/download/v#{version}/keelix-darwin-amd64"
      sha256 "REPLACE_WITH_SHA256"
    end
  end

  on_linux do
    on_arm do
      url "https://github.com/jwlamon/keelix/releases/download/v#{version}/keelix-linux-arm64"
      sha256 "REPLACE_WITH_SHA256"
    end
    on_intel do
      url "https://github.com/jwlamon/keelix/releases/download/v#{version}/keelix-linux-amd64"
      sha256 "REPLACE_WITH_SHA256"
    end
  end

  def install
    bin.install Dir["keelix-*"].first => "keelix"
  end

  test do
    assert_match "keelix", shell_output("#{bin}/keelix version")
  end
end
