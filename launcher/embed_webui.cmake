#
# embed_webui.cmake
# ~~~~~~~~~~~~~~~~
#
# Distributed under the Boost Software License, Version 1.0. (See accompanying
# file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
#
# 把 server/launcher/webui 目录下的全部静态资源编译期内嵌到 launcher 可执行文件
# 中（静态资源直接编入可执行文件），生成 webui_embedded.cpp。
#
# 用法（由 CMakeLists.txt 在构建时调用）：
#   cmake -DINPUT_DIR=<webui 目录> -DOUTPUT_CPP=<输出 .cpp> -P embed_webui.cmake
#

if (NOT DEFINED INPUT_DIR OR NOT DEFINED OUTPUT_CPP)
	message(FATAL_ERROR "embed_webui.cmake: INPUT_DIR and OUTPUT_CPP are required")
endif()

file(GLOB_RECURSE FILES RELATIVE "${INPUT_DIR}" "${INPUT_DIR}/*")
list(SORT FILES)

set(out "// 由 embed_webui.cmake 构建期自动生成，请勿手工编辑。\n")
string(APPEND out "// WebUI 静态资源内嵌（静态资源直接编入可执行文件）。\n")
string(APPEND out "\n")
string(APPEND out "#include \"webui_embedded.hpp\"\n")
string(APPEND out "\n")
string(APPEND out "#include <map>\n")
string(APPEND out "#include <string>\n")
string(APPEND out "\n")
string(APPEND out "namespace launcher {\n")
string(APPEND out "namespace {\n")
string(APPEND out "\n")

set(idx 0)
foreach (f ${FILES})
	file(READ "${INPUT_DIR}/${f}" content HEX)
	string(LENGTH "${content}" hex_len)
	math(EXPR content_len "${hex_len} / 2")
	set(var "k_file_${idx}")
	string(APPEND out "// ${f} (${content_len} bytes)\n")
	string(APPEND out "const unsigned char ${var}[] = {\n")
	set(i 0)
	set(step 76)
	while (i LESS hex_len)
		# 逐块把 hex 字符转换为 0xNN, 序列. 对整串做正则替换或逐字节
		# 循环在 CMake 3.29 (alpine 3.20) 上会退化为 O(n^2), 耗时数十
		# 分钟; 分块后每次只处理 152 字符, 速度提升两个数量级.
		string(SUBSTRING "${content}" ${i} ${step} hexline)
		string(REGEX REPLACE "([0-9a-fA-F][0-9a-fA-F])" "0x\\1," hexline "${hexline}")
		string(APPEND out "  ${hexline}\n")
		math(EXPR i "${i} + ${step}")
	endwhile()
	string(APPEND out "};\n")
	string(APPEND out "\n")
	math(EXPR idx "${idx} + 1")
endforeach()

string(APPEND out "const std::map<std::string, embedded_file, std::less<>> kFiles = {\n")
set(idx 0)
foreach (f ${FILES})
	string(APPEND out "  {\"${f}\", {k_file_${idx}, sizeof(k_file_${idx})}},\n")
	math(EXPR idx "${idx} + 1")
endforeach()
string(APPEND out "};\n")
string(APPEND out "\n")
string(APPEND out "} // namespace\n")
string(APPEND out "\n")
string(APPEND out "const embedded_file* find_embedded_file(const std::string& path) {\n")
string(APPEND out "  auto it = kFiles.find(path);\n")
string(APPEND out "  if (it == kFiles.end())\n")
string(APPEND out "    return nullptr;\n")
string(APPEND out "  return &it->second;\n")
string(APPEND out "}\n")
string(APPEND out "\n")
string(APPEND out "} // namespace launcher\n")

file(WRITE "${OUTPUT_CPP}" "${out}")
message(STATUS "embed_webui: embedded ${idx} files from ${INPUT_DIR}")
