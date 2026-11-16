package tech.thessemaj.deviceintelligence.gradle.tasks

import org.gradle.api.DefaultTask
import org.gradle.api.file.DirectoryProperty
import org.gradle.api.file.RegularFileProperty
import org.gradle.api.provider.Property
import org.gradle.api.tasks.Input
import org.gradle.api.tasks.OutputDirectory
import org.gradle.api.tasks.OutputFile
import org.gradle.api.tasks.TaskAction

/**
 * Spec 08 (Stage A) — generates the Project DeviceIntelligence bootstrap entry points
 * INTO THE CONSUMER APP with per-build randomized names, instead of shipping them
 * as the telltale `DeviceIntelligenceInitProvider` / `DeviceIntelligenceComponentFactory`
 * classes in the AAR (which R8 cannot rename — they are manifest/JNI-referenced by
 * name, so a `-keep` pins them and any APK reader finds the whole bootstrap by name).
 *
 * Emits two Java sources (a ContentProvider + an AppComponentFactory) under a random
 * package/class name and a manifest fragment wiring them with a random provider
 * authority. The generated provider does exactly what the old one did — load the
 * native lib, cache the app Context into [FrameworkShim], and kick `nativeOrchestrate`
 * on a daemon thread — but carries no recognisable name.
 *
 * The names are computed once by the plugin (per build) and passed in as inputs so
 * the sources and the manifest agree. The class/method surface of NativeBridge /
 * FrameworkShim is still fixed (the prebuilt .so binds to it by name); Stage B
 * collapses that to a single anchor so those can be generated + randomized too.
 */
abstract class GenerateBootstrapTask : DefaultTask() {

    /** Random package the generated bootstrap classes live in (e.g. `a.b.c`). */
    @get:Input
    abstract val packageName: Property<String>

    /** Random simple name of the generated ContentProvider. */
    @get:Input
    abstract val providerClass: Property<String>

    /** Random simple name of the generated AppComponentFactory. */
    @get:Input
    abstract val factoryClass: Property<String>

    /** Random suffix for the provider authority (`${applicationId}.<suffix>`). */
    @get:Input
    abstract val authoritySuffix: Property<String>

    @get:Input
    abstract val variantName: Property<String>

    /** Generated `.java` sources, wired into the consumer variant's source set. */
    @get:OutputDirectory
    abstract val outputSourceDir: DirectoryProperty

    /** Generated manifest fragment, wired into the variant's manifest pipeline. */
    @get:OutputFile
    abstract val outputManifest: RegularFileProperty

    @TaskAction
    fun generate() {
        val pkg = packageName.get()
        val prov = providerClass.get()
        val fact = factoryClass.get()
        val authority = authoritySuffix.get()

        val srcRoot = outputSourceDir.get().asFile
        srcRoot.deleteRecursively()
        val pkgDir = srcRoot.resolve(pkg.replace('.', '/'))
        pkgDir.mkdirs()

        pkgDir.resolve("$prov.java").writeText(providerSource(pkg, prov))
        pkgDir.resolve("$fact.java").writeText(factorySource(pkg, fact))

        val man = outputManifest.get().asFile
        man.parentFile?.mkdirs()
        man.writeText(manifestFragment(pkg, prov, fact, authority))
    }

    private fun providerSource(pkg: String, cls: String): String = """
        package $pkg;

        import android.content.ContentProvider;
        import android.content.ContentValues;
        import android.content.Context;
        import android.database.Cursor;
        import android.net.Uri;

        import tech.thessemaj.deviceintelligence.internal.FrameworkShim;
        import tech.thessemaj.deviceintelligence.dx.NativeBridge;

        /** Generated bootstrap (spec 08). Do not edit. */
        public final class $cls extends ContentProvider {
            // Earliest bootstrap: register the framework shim + context so the native
            // up-calls (attestation / apk / cloner inputs) resolve. Detection itself is
            // app-driven now (NativeBridge.initialize + NativeBridge.challenge), so there is no orchestrator
            // call to make here.
            @Override public boolean onCreate() {
                Context ctx = getContext();
                if (ctx == null) return false;
                try { NativeBridge.INSTANCE.isReady(); } catch (Throwable t) { /* native load fail -> degrade */ }
                try { NativeBridge.s(FrameworkShim.class); } catch (Throwable t) { /* ignore */ }
                try { FrameworkShim.setContext(ctx); } catch (Throwable t) { /* ignore */ }
                return true;
            }

            @Override public Cursor query(Uri u, String[] p, String s, String[] a, String o) { return null; }
            @Override public String getType(Uri u) { return null; }
            @Override public Uri insert(Uri u, ContentValues v) { return null; }
            @Override public int delete(Uri u, String s, String[] a) { return 0; }
            @Override public int update(Uri u, ContentValues v, String s, String[] a) { return 0; }
        }
    """.trimIndent() + "\n"

    private fun factorySource(pkg: String, cls: String): String = """
        package $pkg;

        import android.annotation.TargetApi;
        import android.app.AppComponentFactory;
        import android.app.Application;

        import tech.thessemaj.deviceintelligence.dx.NativeBridge;

        /** Generated earliest-bootstrap (spec 08). Do not edit. */
        @TargetApi(28)
        public final class $cls extends AppComponentFactory {
            @Override public Application instantiateApplication(ClassLoader cl, String className)
                    throws InstantiationException, IllegalAccessException, ClassNotFoundException {
                try { NativeBridge.INSTANCE.isReady(); } catch (Throwable t) { /* degrade to provider path */ }
                return super.instantiateApplication(cl, className);
            }
        }
    """.trimIndent() + "\n"

    private fun manifestFragment(pkg: String, prov: String, fact: String, authority: String): String = """
        <?xml version="1.0" encoding="utf-8"?>
        <manifest xmlns:android="http://schemas.android.com/apk/res/android"
            xmlns:tools="http://schemas.android.com/tools">
            <application
                android:appComponentFactory="$pkg.$fact"
                tools:targetApi="28"
                tools:replace="android:appComponentFactory">
                <provider
                    android:name="$pkg.$prov"
                    android:authorities="${'$'}{applicationId}.$authority"
                    android:exported="false"
                    android:initOrder="2147483647" />
            </application>
        </manifest>
    """.trimIndent() + "\n"
}
