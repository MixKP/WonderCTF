<script setup lang="ts">
import { onMounted, ref } from 'vue'
import apiClient from '@/api/client'
import type { ScoreboardEntry } from '@/types'

const entries = ref<ScoreboardEntry[]>([])
const loading = ref(true)

onMounted(async () => {
  try {
    const { data } = await apiClient.get<ScoreboardEntry[]>('/api/scoreboard')
    entries.value = data
  } finally {
    loading.value = false
  }
})
</script>

<template>
  <div>
    <h1 class="mb-6 text-2xl font-semibold text-white">Scoreboard</h1>

    <p v-if="loading" class="text-gray-400">Loading…</p>

    <table v-else class="w-full overflow-hidden rounded-lg border border-ctf-border text-left text-sm">
      <thead class="bg-ctf-panel text-gray-400">
        <tr>
          <th class="px-4 py-2">#</th>
          <th class="px-4 py-2">Player</th>
          <th class="px-4 py-2">Solved</th>
          <th class="px-4 py-2">Score</th>
        </tr>
      </thead>
      <tbody>
        <tr v-for="(entry, i) in entries" :key="entry.userId" class="border-t border-ctf-border">
          <td class="px-4 py-2 text-gray-500">{{ i + 1 }}</td>
          <td class="px-4 py-2 text-white">{{ entry.username }}</td>
          <td class="px-4 py-2 text-gray-300">{{ entry.solvedCount }}</td>
          <td class="px-4 py-2 font-medium text-ctf-accent">{{ entry.score }}</td>
        </tr>
      </tbody>
    </table>

    <p v-if="!loading && entries.length === 0" class="text-gray-500">No scores yet.</p>
  </div>
</template>
