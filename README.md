# BundleInfo
A simple JAR parser which obtains and logs information, such as MANIFEST.MF entries and code signers.

## Build
Kotlin runtime is required.

`kotlinc BundleInfo.kt -include-runtime -d bundleinfo.jar`

## Usage
`java -jar bundleinfo.jar`

Choose a jar-file.
