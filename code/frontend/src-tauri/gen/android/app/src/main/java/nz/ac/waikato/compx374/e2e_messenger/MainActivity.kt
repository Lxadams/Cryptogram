package nz.ac.waikato.compx374.e2e_messenger

import android.Manifest
import android.content.pm.PackageManager
import android.os.Build
import android.os.Bundle
import android.view.View
import androidx.activity.enableEdgeToEdge
import androidx.core.app.ActivityCompat
import androidx.core.content.ContextCompat
import androidx.core.view.ViewCompat
import androidx.core.view.WindowInsetsCompat

class MainActivity : TauriActivity() {
  override fun onCreate(savedInstanceState: Bundle?) {
    // Screen capture is allowed (no FLAG_SECURE), so the phone can be
    // mirrored to a laptop (e.g. with scrcpy) to demo the app.
    enableEdgeToEdge()
    super.onCreate(savedInstanceState)
    keepClearOfSystemBars()
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

  override fun onResume() {
    super.onResume()
    NativeBridge.appResumed()
    MessageService.clearMessageNotifications(this)
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
