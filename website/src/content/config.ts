import { defineCollection } from 'astro:content';

const exercisesCollection = defineCollection({
  type: 'content',
});

export const collections = {
  exercises: exercisesCollection,
};
