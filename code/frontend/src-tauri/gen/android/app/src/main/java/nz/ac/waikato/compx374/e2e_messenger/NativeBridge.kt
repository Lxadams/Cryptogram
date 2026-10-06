package nz.ac.waikato.compx374.e2e_messenger

import android.content.Context
import android.os.Handler
import android.os.Looper
import androidx.lifecycle.DefaultLifecycleObserver
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.LifecycleOwner
import androidx.lifecycle.ProcessLifecycleOwner
import java.util.concurrent.atomic.AtomicBoolean

/**
 * Kotlin half of the bridge in src-tauri/src/background.rs. A thread waits
 * in [nextEvent] for what the Rust backend reports, and keeps the app
 * receiving messages while it isn't on screen:
 * - while someone is logged in, [MessageService] runs as a foreground
 *   service, so Android doesn't freeze the process and its UDP socket;
 * - a message that arrives while the app is in the background gets a
 *   notification.
 *
 * It also tells the backend when the app comes on or goes off screen
 * ([appVisible]), so it can pause presence pings to save battery.
 */
object NativeBridge {
    init {
        System.loadLibrary("e2e_messenger_lib")
    }

    /**
     * Blocks until the backend's next event: `"session_started"`,
     * `"session_ended"` or `"message\t<from>"`.
     */
    @JvmStatic external fun nextEvent(): String?

    /** Tells the backend the app is back on screen, so it syncs with the relay at once. */
    @JvmStatic external fun appResumed()

    /** Tells the backend whether any of the app is visible. */
    @JvmStatic external fun appVisible(visible: Boolean)

    private val started = AtomicBoolean(false)

    /** Starts the event thread and visibility reports, once per process. */
    fun start(context: Context) {
        if (!started.compareAndSet(false, true)) return
        ProcessLifecycleOwner.get().lifecycle.addObserver(object : DefaultLifecycleObserver {
            override fun onStart(owner: LifecycleOwner) = appVisible(true)
            override fun onStop(owner: LifecycleOwner) = appVisible(false)
        })
        val appContext = context.applicationContext
        val mainThread = Handler(Looper.getMainLooper())
        Thread({
            while (true) {
                val event = nextEvent() ?: continue
                mainThread.post { handle(appContext, event) }
            }
        }, "e2e-background-events").apply {
            isDaemon = true
            start()
        }
    }

    private fun handle(context: Context, event: String) {
        when {
            event == "session_started" -> MessageService.start(context)
            event == "session_ended" -> MessageService.stop(context)
            event.startsWith("message\t") -> {
                val onScreen = ProcessLifecycleOwner.get().lifecycle.currentState
                    .isAtLeast(Lifecycle.State.STARTED)
                if (!onScreen) {
                    MessageService.notifyMessage(context, event.removePrefix("message\t"))
                }
            }
        }
    }
}
