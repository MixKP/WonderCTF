<script setup lang="ts">
import { ref, onMounted } from 'vue'
import { useRoute } from 'vue-router'
import { useChallengesStore } from '@/stores/challenges'
import FlagSubmitForm from '@/components/FlagSubmitForm.vue'
import type { Challenge } from '@/types'

const route = useRoute()
const store = useChallengesStore()

const challenge = ref<Challenge | null>(null)
const loading = ref(true)
const notFound = ref(false)

onMounted(async () => {
  try {
    challenge.value = await store.fetchChallenge(route.params.id as string)
  } catch {
    notFound.value = true
  } finally {
    loading.value = false
  }
})
</script>

<template>
  <div class="mx-auto max-w-2xl">
    <RouterLink to="/" class="text-sm text-gray-400 hover:text-ctf-accent">&larr; All challenges</RouterLink>

    <p v-if="loading" class="mt-6 text-gray-400">Loading…</p>
    <p v-else-if="notFound" class="mt-6 text-red-400">Challenge not found.</p>

    <div v-else-if="challenge" class="mt-4">
      <span class="text-xs font-mono uppercase tracking-wide text-gray-500">{{ challenge.category }}</span>
      <h1 class="mt-1 text-2xl font-semibold text-white">{{ challenge.title }}</h1>
      <p class="mt-1 text-sm text-ctf-accent">{{ challenge.points }} pts</p>

      <p class="mt-4 text-gray-300">{{ challenge.description }}</p>

      <a
        :href="challenge.url"
        target="_blank"
        rel="noopener noreferrer"
        class="mt-4 inline-block rounded border border-ctf-border px-4 py-2 text-sm text-gray-200 hover:border-ctf-accent hover:text-ctf-accent"
      >
        Open challenge &rarr;
      </a>

      <div class="mt-6">
        <FlagSubmitForm :challenge-id="challenge.id" :already-solved="challenge.solved" />
      </div>
    </div>
  </div>
</template>
