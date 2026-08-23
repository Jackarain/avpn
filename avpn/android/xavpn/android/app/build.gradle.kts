import com.android.build.gradle.BaseExtension

plugins {
    id("com.android.application")
    id("kotlin-android")
    // The Flutter Gradle Plugin must be applied after the Android and Kotlin Gradle plugins.
    id("dev.flutter.flutter-gradle-plugin")
}

android {
    namespace = "com.jackarain.xavpn"
    compileSdk = flutter.compileSdkVersion
    ndkVersion = flutter.ndkVersion

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_11
        targetCompatibility = JavaVersion.VERSION_11
    }

    kotlinOptions {
        jvmTarget = JavaVersion.VERSION_11.toString()
    }

    defaultConfig {
        // TODO: Specify your own unique Application ID (https://developer.android.com/studio/build/application-id.html).
        applicationId = "com.jackarain.xavpn"
        // You can update the following values to match your application needs.
        // For more information, see: https://flutter.dev/to/review-gradle-config.
        // VpnService.protect(int) 需要 API 22+, 这里直接使用 23.
        minSdk = 23
        targetSdk = flutter.targetSdkVersion
        versionCode = flutter.versionCode
        versionName = flutter.versionName
    }

    buildTypes {
        release {
            // TODO: Add your own signing config for the release build.
            // Signing with the debug keys for now, so `flutter run --release` works.
            signingConfig = signingConfigs.getByName("debug")
            // SWIG/JNI 类不可混淆, 否则 native RegisterNatives 会找不到方法.
            proguardFiles(
                getDefaultProguardFile("proguard-android-optimize.txt"),
                "proguard-rules.pro",
            )
        }
    }
}

dependencies {
    implementation("androidx.core:core-ktx:1.13.1")
}

flutter {
    source = "../.."
}

// 构建 APK 前, 将 build.android.sh 编译出的 libxavpn.so 同步到 jniLibs 对应的 ABI 目录;
// 若 release/<abi> 下缺少产物, 则先调用 build.android.sh 全量编译原生库.
val syncXavpnLibs = tasks.register("syncXavpnLibs") {
    group = "build"
    description = "将编译产物 libxavpn.so 复制到 src/main/jniLibs 对应的 ABI 目录"

    val repoRoot = rootProject.projectDir.parentFile?.parentFile?.parentFile?.parentFile
        ?: throw GradleException("无法定位 avpn 仓库根目录: ${rootProject.projectDir}")
    check(File(repoRoot, "build.android.sh").isFile) {
        "无法定位 avpn 仓库根目录 (未找到 build.android.sh): ${repoRoot.absolutePath}"
    }
    val jniLibsRoot = project.layout.projectDirectory.dir("src/main/jniLibs")
    val abis = listOf("arm64-v8a", "armeabi-v7a", "x86", "x86_64")

    doLast {
        val releaseDir = File(repoRoot, "release")
        if (abis.any { abi -> !File(releaseDir, "$abi/libxavpn.so").isFile }) {
            logger.lifecycle("release/ 下缺少 libxavpn.so, 调用 build.android.sh 编译原生库...")
            buildXavpnLibs(repoRoot, logger)
        }
        abis.forEach { abi ->
            val src = File(releaseDir, "$abi/libxavpn.so")
            if (!src.isFile) {
                throw GradleException("缺少 $abi 的 libxavpn.so, 请先运行仓库根目录下的 ./build.android.sh")
            }
            val dstDir = jniLibsRoot.dir(abi).asFile
            dstDir.mkdirs()
            src.copyTo(File(dstDir, "libxavpn.so"), overwrite = true)
            logger.lifecycle("已同步 jniLibs/$abi/libxavpn.so")
        }
    }
}

fun buildXavpnLibs(repoRoot: File, logger: org.gradle.api.logging.Logger) {
    val ndkDir = resolveNdkDir(project)
    val hostTag = when {
        System.getProperty("os.name").contains("Linux", ignoreCase = true) -> "linux-x86_64"
        System.getProperty("os.name").contains("Mac", ignoreCase = true) -> "darwin-x86_64"
        else -> "windows-x86_64"
    }
    logger.lifecycle("使用 NDK: ${ndkDir.absolutePath}")
    val proc = ProcessBuilder("./build.android.sh", repoRoot.absolutePath, ndkDir.absolutePath, hostTag)
        .directory(repoRoot)
        .redirectErrorStream(true)
        .start()
    proc.inputStream.bufferedReader().useLines { lines ->
        lines.forEach { logger.lifecycle(it) }
    }
    if (proc.waitFor() != 0) {
        throw GradleException("build.android.sh 编译失败, 请检查上方日志")
    }
}

fun resolveNdkDir(project: Project): File {
    val androidExt = project.extensions.findByName("android")
    if (androidExt is BaseExtension) {
        runCatching { androidExt.ndkDirectory }.getOrNull()?.takeIf { it.isDirectory }?.let { return it }
        runCatching { androidExt.sdkDirectory }.getOrNull()?.let { sdk ->
            findSdkNdk(sdk)?.let { return it }
        }
    }
    listOf("ANDROID_NDK_HOME", "ANDROID_NDK_ROOT").forEach { name ->
        System.getenv(name)?.let { path ->
            File(path).takeIf { it.isDirectory }?.let { return it }
        }
    }
    System.getenv("ANDROID_HOME")?.let { sdk ->
        findSdkNdk(File(sdk))?.let { return it }
    }
    throw GradleException("未找到 NDK: 请通过 SDK Manager 安装 NDK, 或设置 ANDROID_NDK_HOME/ANDROID_NDK_ROOT")
}

fun findSdkNdk(sdk: File): File? {
    val roots = listOf(File(sdk, "ndk"), File(sdk, "ndk-bundle")).filter { it.isDirectory }
    val installed = roots.flatMap { it.listFiles()?.toList() ?: emptyList() }.filter { it.isDirectory }
    return installed.maxByOrNull { it.name }
}

tasks.named("preBuild") {
    dependsOn(syncXavpnLibs)
}
