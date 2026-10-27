# Privacy: remove all logging from release builds
-assumenosideeffects class android.util.Log {
    public static *** v(...);
    public static *** d(...);
    public static *** i(...);
    public static *** w(...);
    public static *** e(...);
}

# JNI: Rust looks these methods up by exact class and method name
-keep class io.github.xer0bit.nullveil.Native { native <methods>; }
