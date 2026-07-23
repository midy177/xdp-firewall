<template>
  <button class="ui-button" :class="variant" v-bind="$attrs">
    <slot />
  </button>
</template>

<script setup lang="ts">
withDefaults(
  defineProps<{
    variant?: "primary" | "secondary" | "ghost" | "danger";
  }>(),
  {
    variant: "primary"
  }
);
</script>
