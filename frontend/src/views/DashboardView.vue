<script setup lang="ts">
import { onMounted } from 'vue'
import { useChallengesStore } from '@/stores/challenges'
import ChallengeCard from '@/components/ChallengeCard.vue'

const store = useChallengesStore()

onMounted(() => {
  store.fetchChallenges()
})
</script>

<template>
  <div>
    <h1 class="mb-6 text-2xl font-semibold text-white">Challenges</h1>

    <p v-if="store.loading" class="text-gray-400">Loading challenges…</p>

    <div v-else class="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-3">
      <ChallengeCard v-for="ch in store.challenges" :key="ch.id" :challenge="ch" />
    </div>

    <p v-if="!store.loading && store.challenges.length === 0" class="text-gray-500">
      No challenges available yet.
    </p>
  </div>
</template>
