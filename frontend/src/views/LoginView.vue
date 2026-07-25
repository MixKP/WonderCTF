<script setup lang="ts">
import { ref } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { useAuthStore } from '@/stores/auth'
import { apiErrorMessage } from '@/api/client'

const auth = useAuthStore()
const router = useRouter()
const route = useRoute()

const username = ref('')
const password = ref('')
const error = ref('')
const submitting = ref(false)

async function handleSubmit() {
  error.value = ''
  submitting.value = true
  try {
    await auth.login(username.value, password.value)
    const redirect = (route.query.redirect as string) || '/'
    router.push(redirect)
  } catch (err) {
    error.value = apiErrorMessage(err, 'Login failed')
  } finally {
    submitting.value = false
  }
}
</script>

<template>
  <div class="mx-auto mt-12 max-w-sm">
    <h1 class="mb-6 text-2xl font-semibold text-white">Log in</h1>

    <form class="space-y-4" @submit.prevent="handleSubmit">
      <div>
        <label for="username" class="mb-1 block text-sm text-gray-400">Username</label>
        <input
          id="username"
          v-model="username"
          type="text"
          required
          autocomplete="username"
          class="w-full rounded border border-ctf-border bg-ctf-panel px-3 py-2 text-white focus:border-ctf-accent focus:outline-none"
        />
      </div>

      <div>
        <label for="password" class="mb-1 block text-sm text-gray-400">Password</label>
        <input
          id="password"
          v-model="password"
          type="password"
          required
          autocomplete="current-password"
          class="w-full rounded border border-ctf-border bg-ctf-panel px-3 py-2 text-white focus:border-ctf-accent focus:outline-none"
        />
      </div>

      <p v-if="error" class="text-sm text-red-400">{{ error }}</p>

      <button
        type="submit"
        :disabled="submitting"
        class="w-full rounded bg-ctf-accent-dim px-4 py-2 font-medium text-white hover:bg-ctf-accent hover:text-ctf-bg disabled:opacity-50"
      >
        {{ submitting ? 'Logging in…' : 'Log in' }}
      </button>
    </form>

    <p class="mt-4 text-sm text-gray-400">
      No account?
      <RouterLink to="/register" class="text-ctf-accent hover:underline">Register</RouterLink>
    </p>
  </div>
</template>
