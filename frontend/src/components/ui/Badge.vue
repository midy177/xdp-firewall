<template>
  <span class="ui-badge" :class="tone">
    <slot />
  </span>
</template>

<script setup lang="ts">
withDefaults(
  defineProps<{
    tone?: "neutral" | "green" | "red" | "amber";
  }>(),
  {
    tone: "neutral"
  }
);
</script>
