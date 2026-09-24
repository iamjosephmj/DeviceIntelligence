package tech.thessemaj.deviceintelligence.sample.di

import tech.thessemaj.deviceintelligence.sample.data.IntelScanRepository
import tech.thessemaj.deviceintelligence.sample.domain.ScanRepository
import dagger.Binds
import dagger.Module
import dagger.Provides
import dagger.hilt.InstallIn
import dagger.hilt.components.SingletonComponent
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.Dispatchers
import javax.inject.Singleton

@Module
@InstallIn(SingletonComponent::class)
abstract class RepositoryModule {

    @Binds
    @Singleton
    abstract fun bindScanRepository(impl: IntelScanRepository): ScanRepository
}

@Module
@InstallIn(SingletonComponent::class)
object DispatcherModule {

    /**
     * Injected rather than referenced directly so ViewModel tests can substitute a
     * test dispatcher without touching the Android framework.
     */
    @Provides
    @Singleton
    fun provideIoDispatcher(): CoroutineDispatcher = Dispatchers.IO
}
