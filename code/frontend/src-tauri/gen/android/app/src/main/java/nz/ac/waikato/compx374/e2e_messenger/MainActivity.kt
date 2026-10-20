package nz.ac.waikato.compx374.e2e_messenger

import android.Manifest
import android.content.pm.PackageManager
import android.os.Build
import android.os.Bundle
import android.view.View
import android.webkit.WebView
import androidx.activity.OnBackPressedCallback
import androidx.activity.enableEdgeToEdge
import androidx.core.app.ActivityCompat
import androidx.core.content.ContextCompat
import androidx.core.view.ViewCompat
import androidx.core.view.WindowInsetsCompat

class MainActivity : TauriActivity() {
  private var webView: WebView? = null

  override fun onCreate(savedInstanceState: Bundle?) {
    // Screen capture is allowed (no FLAG_SECURE), so the phone can be
    // mirrored to a laptop (e.g. with scrcpy) to demo the app.
    enableEdgeToEdge()
    super.onCreate(savedInstanceState)
    keepClearOfSystemBars()
    askThePageOnBack()
    NativeBridge.start(this)
    // For new-message notifications (see MessageService). Android 13+ only;
    // older versions allow notifications without asking.
    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU &&
      ContextCompat.checkSelfPermission(this, Manifest.permission.POST_NOTIFICATIONS)
      != PackageManager.PERMISSION_GRANTED
    ) {
      ActivityCompat.requestPermissions(this, arrayOf(Manifest.permission.POST_NOTIFICATIONS), 0)
    }
  }

  override fun onWebViewCreate(webView: WebView) {
    this.webView = webView
  }

  override fun onResume() {
    super.onResume()
    NativeBridge.appResumed()
    MessageService.clearMessageNotifications(this)
  }

  /**
   * Android's back button: the page closes whatever is open on top, such as
   * a chat or a QR code (`window.__cryptogramBack`, see back_button.rs), and
   * only with nothing open does back go on to Android's default, which puts
   * the app in the background. Tauri's own back handling (its AppPlugin) is
   * attached to the first activity only: once the app had been closed and
   * reopened while it kept running for MessageService, this activity was a
   * new one, and back left the app from anywhere until a force stop. This
   * is attached to every activity.
   */
  private fun askThePageOnBack() {
    onBackPressedDispatcher.addCallback(this, object : OnBackPressedCallback(true) {
      override fun handleOnBackPressed() {
        val page = webView ?: return goOn()
        page.evaluateJavascript(
          "window.__cryptogramBack ? window.__cryptogramBack() : false",
        ) { closedSomething -> if (closedSomething != "true") goOn() }
      }

      // What back would do without this: any other handler (Tauri's, on the
      // first activity), then Android's default.
      fun goOn() {
        isEnabled = false
        onBackPressedDispatcher.onBackPressed()
        isEnabled = true
      }
    })
  }

  /**
   * Edge-to-edge (always on from Android 15) draws the app under the status
   * bar, navigation bar and keyboard. Pad the web view's container by those
   * insets so none of them cover the UI, including the chat input while
   * typing. Done here rather than with CSS `env(safe-area-inset-*)`, which
   * older Android WebViews report as zero.
   */
  private fun keepClearOfSystemBars() {
    val content = findViewById<View>(android.R.id.content)
    ViewCompat.setOnApplyWindowInsetsListener(content) { view, insets ->
      val bars = insets.getInsets(
        WindowInsetsCompat.Type.systemBars() or WindowInsetsCompat.Type.displayCutout(),
      )
      val keyboard = insets.getInsets(WindowInsetsCompat.Type.ime())
      view.setPadding(bars.left, bars.top, bars.right, maxOf(bars.bottom, keyboard.bottom))
      WindowInsetsCompat.CONSUMED
    }
  }
}
