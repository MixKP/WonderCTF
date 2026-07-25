<script setup lang="ts">
import type { Challenge } from '@/types'

defineProps<{ challenge: Challenge }>()
</script>

<template>
  <RouterLink
    :to="`/challenges/${challenge.id}`"
    class="block rounded-lg border p-4 transition"
    :class="
      challenge.solved
        ? 'border-emerald-700/60 bg-emerald-950/30 hover:border-emerald-500'
        : 'border-ctf-border bg-ctf-panel hover:border-ctf-accent'
    "
  >
    <div class="flex items-start justify-between gap-2">
      <span class="text-xs font-mono uppercase tracking-wide text-gray-500">{{ challenge.category }}</span>
      <span
        v-if="challenge.solved"
        class="rounded-full bg-emerald-800/60 px-2 py-0.5 text-xs font-medium text-emerald-300"
      >
        Solved
      </span>
    </div>
    <h3 class="mt-2 text-lg font-semibold text-white">{{ challenge.title }}</h3>
    <p class="mt-1 line-clamp-2 text-sm text-gray-400">{{ challenge.description }}</p>
    <div class="mt-3 text-sm font-medium text-ctf-accent">{{ challenge.points }} pts</div>
  </RouterLink>
</template>
