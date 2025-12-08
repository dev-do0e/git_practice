#!/usr/bin/env bash
#set -e  # 오류 발생 시 즉시 종료

# 1. 기본 툴 설치
# sudo apt update
# sudo apt install -y \
#     build-essential \
#     cmake \
#     ninja-build \
#     libssl-dev \
#     libtbb-dev \
#     libsqlite3-dev \
#     libcurl4-openssl-dev \
#     libssh-dev \
#     zlib1g-dev \
#     liblz4-dev

# 2. 경로 설정
SRC_DIR="/workspace/Developments/Lampad/spin7"
BUILD_DIR="$SRC_DIR/build"
RESULT_LOG="$SRC_DIR/build/result.txt"

# 3. 빌드 디렉토리 초기화
rm -rf "$BUILD_DIR"
mkdir -p "$BUILD_DIR"
cd "$BUILD_DIR"

# 4. CMake 설정 (Ninja + Release)
cmake -G Ninja -DCMAKE_BUILD_TYPE=Release .. 2>&1 | tee "$RESULT_LOG"

# 4. 빌드 실행 (CPU 코어 수 활용)
ninja -j"$(nproc)" 2>&1 | tee -a "$RESULT_LOG"

echo "✅ Spin7 빌드 완료. 실행 파일: $BUILD_DIR/spin7"
echo "📄 빌드 로그는 $RESULT_LOG 에 저장됨"
