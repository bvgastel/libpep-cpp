class LibPEP < Formula
  desc "Polymorphic Encryption and Pseudonimisation library"
  homepage "https://gitlab.science.ru.nl/ilab/libpep"
  #url "https://bitpowder.com:2443/bvgastel/clippy/-/archive/0.1.1/clippy-0.1.1.tar.gz"
  #sha256 "2777e5f5b4f19f93913e2e97187ccc71b61825a85efc48cb0358b2d2e3cca239"
  head "https://gitlab.science.ru.nl/ilab/libpep.git", branch: "main"
  license "BSD-2-Clause"

  depends_on "bsdmake" => :build
  depends_on "cmake" => :build

  def install
    system "cmake", "-DALL_WARNINGS=OFF", "-S", ".", "-B", "build", *std_cmake_args
    system "cmake", "--build", "build", "--target", "install"
  end

  test do
    system "#{bin}/libpepcli"
  end
end
