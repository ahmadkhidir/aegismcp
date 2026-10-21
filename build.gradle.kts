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

        val jbr = file("/home/ahmadkhidir/android-studio/jbr")
        tasks.withType<JavaCompile> {
            options.encoding = "UTF-8"
            options.release.set(21)
            if (System.getenv("JAVA_HOME").isNullOrEmpty() && jbr.exists() && !file("/usr/bin/javac").exists()) {
                options.isFork = true
                options.forkOptions.javaHome = jbr
            }
        }

        tasks.withType<Test> {
            useJUnitPlatform()
            testLogging {
                events("passed", "skipped", "failed")
            }
        }
    }
}
