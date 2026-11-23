import org.gradle.api.plugins.JavaPluginExtension
import org.gradle.jvm.toolchain.JavaLanguageVersion

allprojects {
    group = "dev.aegismcp"
    version = "1.0.0-SNAPSHOT"

    repositories {
        mavenCentral()
    }
}

subprojects {
    // Apply Java configuration only to leaf modules containing sources or build files
    if (file("src").exists() || name == "gateway") {
        apply(plugin = "java")

        // Pin the toolchain to Java 21 so the build resolves against the JDK the wrapper runs on
        // and never against a workstation-specific installation (ADR-002, NFR-001, NFR-002).
        extensions.configure<JavaPluginExtension> {
            toolchain {
                languageVersion.set(JavaLanguageVersion.of(21))
            }
        }

        tasks.withType<JavaCompile> {
            options.encoding = "UTF-8"
            options.release.set(21)
        }

        tasks.withType<Test> {
            useJUnitPlatform()
            testLogging {
                events("passed", "skipped", "failed")
            }
        }
    }
}
