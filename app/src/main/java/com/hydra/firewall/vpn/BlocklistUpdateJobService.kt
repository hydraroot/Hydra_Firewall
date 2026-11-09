package com.hydra.firewall.vpn

import android.app.job.JobInfo
import android.app.job.JobParameters
import android.app.job.JobScheduler
import android.app.job.JobService
import android.content.ComponentName
import android.content.Context
import android.util.Log
import java.util.concurrent.TimeUnit

/**
 * OS-managed periodic refresh for ad/tracker and live threat-domain lists.
 * The system waits for an unmetered network and persists the schedule over
 * reboot. BlocklistUpdater itself binds downloads to a physical network, so
 * the update never depends on Hydra's VPN tunnel.
 */
class BlocklistUpdateJobService : JobService() {
    override fun onStartJob(params: JobParameters): Boolean {
        BlocklistUpdater.updateIfDue(applicationContext) { result ->
            if (!result.success && !result.skipped) {
                Log.w(TAG, "Scheduled blocklist update failed: ${result.error}")
                jobFinished(params, true)
            } else {
                jobFinished(params, false)
            }
        }
        return true
    }

    override fun onStopJob(params: JobParameters): Boolean = true

    companion object {
        private const val TAG = "BlocklistUpdateJob"
        private const val JOB_ID = 36505
        private val INTERVAL_MS = TimeUnit.HOURS.toMillis(24)

        /** Schedules one OS-managed, unmetered refresh about every 24 hours. */
        fun schedule(context: Context) {
            runCatching {
                val app = context.applicationContext
                val scheduler = app.getSystemService(Context.JOB_SCHEDULER_SERVICE) as JobScheduler
                // Do not reset the 24-hour window every time the UI or VPN service starts.
                if (scheduler.getPendingJob(JOB_ID) != null) return
                val job = JobInfo.Builder(
                    JOB_ID,
                    ComponentName(app, BlocklistUpdateJobService::class.java)
                )
                    .setRequiredNetworkType(JobInfo.NETWORK_TYPE_UNMETERED)
                    .setPersisted(true)
                    .setPeriodic(INTERVAL_MS)
                    .build()
                val result = scheduler.schedule(job)
                if (result != JobScheduler.RESULT_SUCCESS) {
                    Log.w(TAG, "Android did not accept the periodic blocklist job")
                }
            }.onFailure { Log.w(TAG, "Could not schedule blocklist job", it) }
        }
    }
}
