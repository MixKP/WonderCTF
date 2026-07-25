<script setup lang="ts">
import { ref } from 'vue'
import { useRouter } from 'vue-router'
import { useAuthStore } from '@/stores/auth'
import { apiErrorMessage } from '@/api/client'

const auth = useAuthStore()
const router = useRouter()

const username = ref('')
const email = ref('')
const password = ref('')
const error = ref('')
const submitting = ref(false)

async function handleSubmit() {
  error.value = ''
  submitting.value = true
  try {
    await auth.register(username.value, email.value, password.value)
    router.push('/')
  } catch (err) {
    error.value = apiErrorMessage(err, 'Registration failed')
  } finally {
    submitting.value = false
  }
}
</script>

<template>
  <div class="mx-auto mt-12 max-w-sm">
    <h1 class="mb-6 text-2xl font-semibold text-white">Create an account</h1>

    <form class="space-y-4" @submit.prevent="handleSubmit">
      <div>
        <label for="username" class="mb-1 block text-sm text-gray-400">Username</label>
        <input
          id="username"
          v-model="username"
          type="text"
          required
          minlength="3"
          maxlength="32"
          pattern="[a-zA-Z0-9_]+"
          autocomplete="username"
          class="w-full rounded border border-ctf-border bg-ctf-panel px-3 py-2 text-white focus:border-ctf-accent focus:outline-none"
        />
      </div>

      <div>
        <label for="email" class="mb-1 block text-sm text-gray-400">Email</label>
        <input
          id="email"
          v-model="email"
          type="email"
          required
          autocomplete="email"
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
          minlength="8"
          autocomplete="new-password"
          class="w-full rounded border border-ctf-border bg-ctf-panel px-3 py-2 text-white focus:border-ctf-accent focus:outline-none"
        />
        <p class="mt-1 text-xs text-gray-500">At least 8 characters.</p>
      </div>

      <p v-if="error" class="text-sm text-red-400">{{ error }}</p>

      <button
        type="submit"
        :disabled="submitting"
        class="w-full rounded bg-ctf-accent-dim px-4 py-2 font-medium text-white hover:bg-ctf-accent hover:text-ctf-bg disabled:opacity-50"
      >
        {{ submitting ? 'Creating account…' : 'Register' }}
      </button>
    </form>

    <p class="mt-4 text-sm text-gray-400">
      Already have an account?
      <RouterLink to="/login" class="text-ctf-accent hover:underline">Log in</RouterLink>
    </p>
  </div>
</template>
