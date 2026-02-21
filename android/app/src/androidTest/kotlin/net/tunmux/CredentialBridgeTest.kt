package net.tunmux

import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class CredentialBridgeTest {
    @Test
    fun test_save_load_delete_and_provider_scope() {
        val context = InstrumentationRegistry.getInstrumentation().targetContext
        CredentialBridge.initialize(context)

        // Best-effort cleanup from prior runs.
        CredentialBridge.delete("proton")
        CredentialBridge.delete("airvpn")

        val protonPayload = "{\"token\":\"abc123\"}"
        val airvpnPayload = "{\"token\":\"air456\"}"

        val saveProton = JSONObject(CredentialBridge.save("proton", protonPayload))
        assertTrue(saveProton.optBoolean("ok"))
        assertEquals(1, saveProton.optInt("version"))
        assertEquals("save", saveProton.optString("operation"))

        val saveAirvpn = JSONObject(CredentialBridge.save("airvpn", airvpnPayload))
        assertTrue(saveAirvpn.optBoolean("ok"))
        assertEquals(1, saveAirvpn.optInt("version"))
        assertEquals("save", saveAirvpn.optString("operation"))

        val loadProton = JSONObject(CredentialBridge.load("proton"))
        assertTrue(loadProton.optBoolean("ok"))
        assertEquals(1, loadProton.optInt("version"))
        assertEquals("load", loadProton.optString("operation"))
        assertEquals(protonPayload, loadProton.optString("payload"))

        val loadAirvpn = JSONObject(CredentialBridge.load("airvpn"))
        assertTrue(loadAirvpn.optBoolean("ok"))
        assertEquals(airvpnPayload, loadAirvpn.optString("payload"))

        val loadMullvad = JSONObject(CredentialBridge.load("mullvad"))
        assertTrue(loadMullvad.optBoolean("ok"))
        assertTrue(loadMullvad.isNull("payload"))

        val deleteAirvpn = JSONObject(CredentialBridge.delete("airvpn"))
        assertTrue(deleteAirvpn.optBoolean("ok"))
        assertEquals(1, deleteAirvpn.optInt("version"))
        assertEquals("delete", deleteAirvpn.optString("operation"))

        val deleteAirvpnAgain = JSONObject(CredentialBridge.delete("airvpn"))
        assertTrue(deleteAirvpnAgain.optBoolean("ok"))

        val stillThere = JSONObject(CredentialBridge.load("proton"))
        assertTrue(stillThere.optBoolean("ok"))
        assertEquals(protonPayload, stillThere.optString("payload"))

        val deleteProton = JSONObject(CredentialBridge.delete("proton"))
        assertTrue(deleteProton.optBoolean("ok"))

        val loadAfterDelete = JSONObject(CredentialBridge.load("proton"))
        assertTrue(loadAfterDelete.optBoolean("ok"))
        assertTrue(loadAfterDelete.isNull("payload"))
    }

    @Test
    fun test_not_initialized_returns_explicit_error() {
        val field = CredentialBridge::class.java.getDeclaredField("appContext")
        field.isAccessible = true
        field.set(CredentialBridge, null)

        val response = JSONObject(CredentialBridge.load("proton"))
        assertTrue(!response.optBoolean("ok"))
        assertEquals(1, response.optInt("version"))
        assertEquals("load", response.optString("operation"))
        assertEquals("context_not_initialized", response.optString("error_code"))
    }
}
