package com.shieldguard.ai.ui.scanners

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.shieldguard.ai.domain.model.Threat
import com.shieldguard.ai.domain.model.Verdict
import com.shieldguard.ai.domain.usecase.ScanUrlUseCase
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import javax.inject.Inject

data class UrlScannerUiState(
    val urlInput: String = "",
    val isLoading: Boolean = false,
    val lastResult: Threat? = null,
    val error: String? = null
)

@HiltViewModel
class UrlScannerViewModel @Inject constructor(
    private val scanUrlUseCase: ScanUrlUseCase
) : ViewModel() {

    private val _uiState = MutableStateFlow(UrlScannerUiState())
    val uiState: StateFlow<UrlScannerUiState> = _uiState.asStateFlow()

    fun onUrlChanged(newUrl: String) {
        _uiState.value = _uiState.value.copy(urlInput = newUrl, error = null)
    }

    fun scanUrl(targetUrl: String? = null) {
        val url = (targetUrl ?: _uiState.value.urlInput).trim()
        if (url.isBlank()) {
            _uiState.value = _uiState.value.copy(error = "Please enter a valid URL to analyze.")
            return
        }

        viewModelScope.launch {
            _uiState.value = _uiState.value.copy(isLoading = true, error = null)
            val result = scanUrlUseCase(url)
            result.onSuccess { threat ->
                _uiState.value = _uiState.value.copy(isLoading = false, lastResult = threat)
            }.onFailure { ex ->
                _uiState.value = _uiState.value.copy(isLoading = false, error = ex.localizedMessage ?: "Analysis failed")
            }
        }
    }
}
