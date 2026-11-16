package tech.thessemaj.deviceintelligence.sample.navigation

import androidx.compose.animation.ExperimentalSharedTransitionApi
import androidx.compose.animation.SharedTransitionLayout
import androidx.compose.animation.core.tween
import androidx.compose.animation.fadeIn
import androidx.compose.animation.fadeOut
import androidx.compose.animation.slideInHorizontally
import androidx.compose.animation.slideOutHorizontally
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.ui.Modifier
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.navigation.NavGraphBuilder
import androidx.navigation.compose.NavHost
import androidx.navigation.compose.composable
import androidx.navigation.compose.rememberNavController
import tech.thessemaj.deviceintelligence.sample.ui.detail.AttestationScreen
import tech.thessemaj.deviceintelligence.sample.ui.detail.ChecksScreen
import tech.thessemaj.deviceintelligence.sample.ui.detail.FingerprintScreen
import tech.thessemaj.deviceintelligence.sample.ui.detail.SessionFactsScreen
import tech.thessemaj.deviceintelligence.sample.ui.detail.SignalsScreen
import tech.thessemaj.deviceintelligence.sample.ui.scan.ScanScreen
import tech.thessemaj.deviceintelligence.sample.ui.scan.ScanViewModel
import androidx.compose.runtime.CompositionLocalProvider
import tech.thessemaj.deviceintelligence.sample.ui.theme.LocalNavAnimatedScope
import tech.thessemaj.deviceintelligence.sample.ui.theme.LocalSharedTransitionScope
import tech.thessemaj.deviceintelligence.sample.ui.theme.Motion
import tech.thessemaj.deviceintelligence.sample.ui.theme.motionDuration

/**
 * The whole navigation graph.
 *
 * The [ScanViewModel] is hoisted to the activity, not scoped per destination, so
 * every detail screen reads the same scan result the summary rows were built from.
 * Back is the framework's — the View implementation had to register an
 * `OnBackInvokedCallback` by hand and swap content views, and got predictive back
 * wrong on API 33+ until it did.
 */
@OptIn(ExperimentalSharedTransitionApi::class)
@Composable
fun SampleNavHost(
    modifier: Modifier = Modifier,
    viewModel: ScanViewModel = hiltViewModel(),
) {
    val navController = rememberNavController()
    val state by viewModel.state.collectAsStateWithLifecycle()
    val back: () -> Unit = { navController.popBackStack() }

    // Motion answers the tap: drilling in moves forward, Back reverses it. Durations
    // collapse to zero when the device has animations off.
    val forward = motionDuration(Motion.Standard)
    val away = motionDuration(Motion.Quick)

    SharedTransitionLayout {
    CompositionLocalProvider(LocalSharedTransitionScope provides this) {
    NavHost(
        navController,
        startDestination = Destination.Scan.route,
        modifier = modifier,
        enterTransition = {
            slideInHorizontally(tween(forward, easing = Motion.Enter)) { it / 4 } +
                fadeIn(tween(forward, easing = Motion.Enter))
        },
        exitTransition = {
            slideOutHorizontally(tween(away, easing = Motion.Exit)) { -it / 10 } +
                fadeOut(tween(away))
        },
        popEnterTransition = {
            slideInHorizontally(tween(forward, easing = Motion.Enter)) { -it / 10 } +
                fadeIn(tween(forward, easing = Motion.Enter))
        },
        popExitTransition = {
            slideOutHorizontally(tween(away, easing = Motion.Exit)) { it / 4 } +
                fadeOut(tween(away))
        },
    ) {
        composable(Destination.Scan.route) {
            CompositionLocalProvider(LocalNavAnimatedScope provides this@composable) {
            ScanScreen(
                state = state,
                onAction = viewModel::onAction,
                onOpenDetail = { navController.navigate(it.route) },
                onChaos = viewModel::onChaos,
            )
            }
        }
        detail(Destination.Attestation) { AttestationScreen(state.result?.attestation, back) }
        detail(Destination.Checks) { ChecksScreen(state.result, back) }
        detail(Destination.Signals) { SignalsScreen(state.result, back) }
        detail(Destination.Fingerprint) { FingerprintScreen(state.result, back) }
        detail(Destination.SessionFacts) {
            SessionFactsScreen(state.result?.session ?: state.boundSession, back)
        }
    }
    }
    }
}

/** Registers one detail destination and publishes its scope for the shared title. */
private fun NavGraphBuilder.detail(
    destination: Destination,
    content: @Composable () -> Unit,
) = composable(destination.route) {
    CompositionLocalProvider(LocalNavAnimatedScope provides this@composable) { content() }
}
