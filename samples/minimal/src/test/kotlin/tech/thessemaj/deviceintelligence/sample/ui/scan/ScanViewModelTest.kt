package tech.thessemaj.deviceintelligence.sample.ui.scan

import tech.thessemaj.deviceintelligence.sample.R
import tech.thessemaj.deviceintelligence.sample.domain.ScanRepository
import tech.thessemaj.deviceintelligence.sample.domain.model.Timed
import tech.thessemaj.deviceintelligence.sample.domain.usecase.InitializeSdk
import tech.thessemaj.deviceintelligence.sample.domain.usecase.RunScan
import tech.thessemaj.deviceintelligence.verifier.ResolvedSignal
import tech.thessemaj.deviceintelligence.verifier.ScanResult
import tech.thessemaj.deviceintelligence.verifier.ScanSession
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.test.StandardTestDispatcher
import kotlinx.coroutines.test.resetMain
import kotlinx.coroutines.test.runTest
import kotlinx.coroutines.test.setMain
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertSame
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test

/**
 * The state machine the screen draws, exercised without a device.
 *
 * These are the transitions that were previously only observable by running the
 * app on real hardware and reading logcat — in particular that a COMPROMISED
 * verdict still stores its session facts, which is the bug the comment in
 * [ScanViewModel] describes.
 */
@OptIn(ExperimentalCoroutinesApi::class)
class ScanViewModelTest {

    private val dispatcher = StandardTestDispatcher()
    private lateinit var repository: FakeScanRepository

    @Before fun setUp() {
        Dispatchers.setMain(dispatcher)
        repository = FakeScanRepository()
    }

    @After fun tearDown() = Dispatchers.resetMain()

    private fun viewModel() = ScanViewModel(
        initializeSdk = InitializeSdk(repository),
        runScan = RunScan(repository),
        repository = repository,
    )

    @Test fun `starts idle offering Initialize`() {
        val state = viewModel().state.value
        assertEquals(ScanAction.Initialize, state.action)
        assertTrue(state.actionEnabled)
        assertNull(state.result)
    }

    @Test fun `warms the core on construction`() = runTest(dispatcher) {
        viewModel()
        dispatcher.scheduler.advanceUntilIdle()
        assertTrue(repository.warmedUp)
    }

    @Test fun `successful initialize enables Scan and reports READY`() = runTest(dispatcher) {
        val vm = viewModel()
        vm.onInitialize()
        dispatcher.scheduler.advanceUntilIdle()

        val state = vm.state.value
        assertEquals(R.string.status_ready, state.verdict)
        assertEquals(Tone.Good, state.verdictTone)
        assertEquals(ScanAction.Scan, state.action)
        assertTrue(state.actionEnabled)
        assertTrue(state.stages.all { it.state != StageState.Running })
    }

    @Test fun `rejected licence still enables Scan`() = runTest(dispatcher) {
        // A rejected licence is not a dead end: scan must still emit a degraded token.
        repository.licensed = false
        val vm = viewModel()
        vm.onInitialize()
        dispatcher.scheduler.advanceUntilIdle()

        assertEquals(R.string.status_no_licence, vm.state.value.verdict)
        assertEquals(ScanAction.Scan, vm.state.value.action)
        assertTrue(vm.state.value.actionEnabled)
    }

    @Test fun `failed attestation still enables Scan`() = runTest(dispatcher) {
        repository.attested = false
        val vm = viewModel()
        vm.onInitialize()
        dispatcher.scheduler.advanceUntilIdle()

        assertEquals(R.string.status_no_attestation, vm.state.value.verdict)
        assertEquals(ScanAction.Scan, vm.state.value.action)
        assertTrue(vm.state.value.actionEnabled)
    }

    @Test fun `clean scan grades TRUSTWORTHY`() = runTest(dispatcher) {
        val vm = initialised()
        vm.onScan()
        dispatcher.scheduler.advanceUntilIdle()

        assertEquals(R.string.verdict_trustworthy, vm.state.value.verdict)
        assertEquals(Tone.Good, vm.state.value.verdictTone)
        assertSame(repository.result, vm.state.value.result)
    }

    @Test fun `a failed auth gate grades REJECT`() = runTest(dispatcher) {
        repository.result = scanResult(ok = false)
        val vm = initialised()
        vm.onScan()
        dispatcher.scheduler.advanceUntilIdle()

        assertEquals(R.string.verdict_reject, vm.state.value.verdict)
        assertEquals(Tone.Bad, vm.state.value.verdictTone)
    }

    @Test fun `a blocking signal grades COMPROMISED on an authentic token`() = runTest(dispatcher) {
        repository.result = scanResult(signals = listOf(blockingSignal()))
        val vm = initialised()
        vm.onScan()
        dispatcher.scheduler.advanceUntilIdle()

        assertEquals(R.string.verdict_compromised, vm.state.value.verdict)
        assertEquals(Tone.Warn, vm.state.value.verdictTone)
    }

    @Test fun `session facts are stored even when the verdict is not clean`() = runTest(dispatcher) {
        // Gating this on r.ok meant a COMPROMISED device could never carry a session,
        // so every later scan died with no fingerprint and almost no checks.
        val session = repository.session
        repository.result = scanResult(deviceIntegrityOk = false, session = session)
        val vm = initialised()
        vm.onScan()
        dispatcher.scheduler.advanceUntilIdle()

        assertEquals(R.string.verdict_compromised, vm.state.value.verdict)
        assertSame(session, vm.state.value.boundSession)
    }

    @Test fun `an empty token reports NO TOKEN and disables Scan`() = runTest(dispatcher) {
        repository.token = ""
        val vm = initialised()
        vm.onScan()
        dispatcher.scheduler.advanceUntilIdle()

        assertEquals(R.string.status_no_token, vm.state.value.verdict)
        assertFalse(vm.state.value.actionEnabled)
    }

    @Test fun `a verifier throw surfaces the exception rather than swallowing it`() = runTest(dispatcher) {
        // A THROW is a bug or an environment gap, never a policy rejection — the
        // Android 9 XDH failure showed as a bare VERIFY ERROR with nothing to go on.
        repository.verifyFailure = IllegalStateException("no XDH provider")
        val vm = initialised()
        vm.onScan()
        dispatcher.scheduler.advanceUntilIdle()

        val state = vm.state.value
        assertEquals(R.string.status_verify_error, state.verdict)
        // The exception survives into the copy as arguments — the Android 9 XDH failure
        // used to reach the screen as a bare "VERIFY ERROR" with nothing to go on.
        assertEquals(R.string.note_verify_error, state.note?.id)
        assertEquals(listOf("IllegalStateException", "no XDH provider"), state.note?.args)
        // Still recoverable: the button comes back as Rescan.
        assertEquals(ScanAction.Rescan, state.action)
        assertTrue(state.actionEnabled)
    }

    @Test fun `buttons are disabled while a phase is in flight`() = runTest(dispatcher) {
        val vm = initialised()
        vm.onScan()
        // Do NOT advance — the coroutine is suspended mid-scan.
        val state = vm.state.value
        assertTrue(state.busy)
        assertFalse(state.actionEnabled)
    }

    @Test fun `the button hands over to Scan once Initialize has run`() = runTest(dispatcher) {
        val vm = initialised()
        assertEquals(ScanAction.Scan, vm.state.value.action)
        assertTrue(vm.state.value.actionEnabled)
    }

    @Test fun `a rejected licence still hands over to Scan`() = runTest(dispatcher) {
        // Not a dead end — the degraded token is the whole point.
        repository.licensed = false
        val vm = viewModel()
        vm.onInitialize()
        dispatcher.scheduler.advanceUntilIdle()
        assertEquals(ScanAction.Scan, vm.state.value.action)
        assertTrue(vm.state.value.actionEnabled)
    }

    @Test fun `a failed keygen still hands over to Scan`() = runTest(dispatcher) {
        repository.attested = false
        val vm = viewModel()
        vm.onInitialize()
        dispatcher.scheduler.advanceUntilIdle()
        assertEquals(ScanAction.Scan, vm.state.value.action)
        assertTrue(vm.state.value.actionEnabled)
    }

    @Test fun `onAction follows the button through the whole flow`() = runTest(dispatcher) {
        // One control, three jobs: the screen only ever calls onAction.
        val vm = viewModel()
        assertEquals(ScanAction.Initialize, vm.state.value.action)

        vm.onAction()
        dispatcher.scheduler.advanceUntilIdle()
        assertEquals(ScanAction.Scan, vm.state.value.action)

        vm.onAction()
        dispatcher.scheduler.advanceUntilIdle()
        assertEquals(ScanAction.Rescan, vm.state.value.action)
        assertNotNull(vm.state.value.result)
    }

    @Test fun `the button becomes Rescan once a scan has run`() = runTest(dispatcher) {
        val vm = initialised()
        assertEquals(ScanAction.Scan, vm.state.value.action)

        vm.onScan()
        dispatcher.scheduler.advanceUntilIdle()
        assertEquals(ScanAction.Rescan, vm.state.value.action)
    }

    @Test fun `a licence blob that never parsed leaves nothing to retry`() = runTest(dispatcher) {
        // The server public key lives in that blob, so no later scan can succeed
        // either — the button says Rescan but is deliberately dead.
        repository.token = ""
        val vm = initialised()
        vm.onScan()
        dispatcher.scheduler.advanceUntilIdle()
        assertEquals(ScanAction.Rescan, vm.state.value.action)
        assertFalse(vm.state.value.actionEnabled)
    }

    @Test fun `the rail records each stage as it settles`() = runTest(dispatcher) {
        val vm = initialised()
        val stages = vm.state.value.stages
        assertEquals(StageState.Done, stages[ScanUiState.LICENCE].state)
        assertEquals(StageState.Done, stages[ScanUiState.SESSION].state)
        assertEquals(StageState.Pending, stages[ScanUiState.SCAN].state)
        // The measured times are what the rail prints under each node.
        assertEquals(12L, stages[ScanUiState.LICENCE].millis)
        assertEquals(340L, stages[ScanUiState.SESSION].millis)
    }

    @Test fun `the rail stops at the stage that failed`() = runTest(dispatcher) {
        repository.attested = false
        val vm = viewModel()
        vm.onInitialize()
        dispatcher.scheduler.advanceUntilIdle()

        val stages = vm.state.value.stages
        assertEquals(StageState.Done, stages[ScanUiState.LICENCE].state)
        assertEquals(StageState.Failed, stages[ScanUiState.SESSION].state)
        assertEquals(StageState.Pending, stages[ScanUiState.SCAN].state)
    }

    @Test fun `a rejected licence never starts the session stage`() = runTest(dispatcher) {
        repository.licensed = false
        val vm = viewModel()
        vm.onInitialize()
        dispatcher.scheduler.advanceUntilIdle()

        val stages = vm.state.value.stages
        assertEquals(StageState.Failed, stages[ScanUiState.LICENCE].state)
        assertEquals(StageState.Pending, stages[ScanUiState.SESSION].state)
    }

    private fun initialised(): ScanViewModel = viewModel().also {
        it.onInitialize()
        dispatcher.scheduler.advanceUntilIdle()
    }
}
