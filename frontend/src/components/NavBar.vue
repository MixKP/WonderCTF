<script setup lang="ts">
import { useRouter } from 'vue-router'
import { useAuthStore } from '@/stores/auth'

const auth = useAuthStore()
const router = useRouter()

function handleLogout() {
  auth.logout()
  router.push({ name: 'login' })
}
</script>

<template>
  <header class="border-b border-ctf-border bg-ctf-panel">
    <nav class="mx-auto flex max-w-5xl items-center justify-between px-6 py-4">
      <RouterLink to="/" class="flex items-center gap-2 text-lg font-semibold text-ctf-accent">
        <span aria-hidden="true">⚑</span>
        OWASP Top 10 CTF
      </RouterLink>

      <div v-if="auth.isAuthenticated" class="flex items-center gap-6 text-sm">
        <RouterLink to="/" class="text-gray-300 hover:text-ctf-accent">Challenges</RouterLink>
        <RouterLink to="/scoreboard" class="text-gray-300 hover:text-ctf-accent">Scoreboard</RouterLink>
        <span class="text-gray-500">{{ auth.username }}</span>
        <button
          type="button"
          class="rounded border border-ctf-border px-3 py-1.5 text-gray-300 hover:border-ctf-accent hover:text-ctf-accent"
          @click="handleLogout"
        >
          Log out
        </button>
      </div>
    </nav>
  </header>
</template>
