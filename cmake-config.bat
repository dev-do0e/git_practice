mkdir build\Release
mkdir build\RelWithDebInfo
cmake --fresh -GNinja -DCMAKE_BUILD_TYPE=Release -DCMAKE_EXPORT_COMPILE_COMMANDS=ON -H. -Bbuild/Release
cmake --fresh -GNinja -DCMAKE_BUILD_TYPE=RelWithDebInfo -H. -Bbuild/RelWithDebInfo