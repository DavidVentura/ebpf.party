export interface ExerciseMetadata {
  slug: string;
  title: string;
  exerciseId: string;
  codeFile?: string;
  incomplete?: boolean;
  layout?: "ExerciseLayout";
  contentPath: string;
}

export interface ChapterMetadata {
  number: number;
  slug: string;
  title: string;
  exercises: ExerciseMetadata[];
}

export interface ContentMetadata {
  chapters: ChapterMetadata[];
}

export const CONTENT_METADATA: ContentMetadata = {
  chapters: [
    {
      number: 0,
      slug: "chapter-0",
      title: "Introduction",
      exercises: [
        {
          slug: "1_theory",
          title: "Intro to eBPF",
          exerciseId: "theory",
          contentPath: "chapter-0/1_theory",
        },
        {
          slug: "2_platform_overview",
          title: "Platform overview",
          exerciseId: "platform-overview",
          codeFile: "1_editor_intro.c",
          contentPath: "chapter-0/2_platform_overview",
        },
      ],
    },
    {
      number: 1,
      slug: "chapter-1",
      title: "Concept familiarization",
      exercises: [
        {
          slug: "1-intro",
          title: "Process context",
          exerciseId: "concept-intro",
          codeFile: "1_ambient_intro.c",
          contentPath: "chapter-1/1-intro",
        },
        {
          slug: "2-reading-data",
          title: "Reading event data",
          exerciseId: "reading-event-data",
          codeFile: "2_event_data.c",
          contentPath: "chapter-1/2-reading-data",
        },
        {
          slug: "3-reading-syscalls",
          title: "Tracing a system call",
          exerciseId: "reading-syscalls",
          codeFile: "3_execve_syscall.c",
          contentPath: "chapter-1/3-reading-syscalls",
        },
        {
          slug: "4-reading-syscall-arrays",
          title: "Reading syscall arrays",
          exerciseId: "read-argv-password",
          codeFile: "4_execve_argv.c",
          contentPath: "chapter-1/4-reading-syscall-arrays",
        },
      ],
    },
    {
      number: 2,
      slug: "chapter-2",
      title: "Stateful eBPF",
      exercises: [
        {
          slug: "intro-maps-and-programs",
          title: "Maps and multiple programs",
          exerciseId: "intro-maps-and-programs",
          codeFile: "0_maps_intro.c",
          contentPath: "chapter-2/intro-maps-and-programs",
        },
        {
          slug: "read-buffer-contents",
          title: "Reading syscall buffers",
          exerciseId: "read-buffer-contents",
          codeFile: "1_read_buffer.c",
          contentPath: "chapter-2/read-buffer-contents",
        },
        {
          slug: "read-file-password",
          title: "Cross-syscall state tracking",
          exerciseId: "read-file-password",
          codeFile: "2_read_file_password.c",
          contentPath: "chapter-2/read-file-password",
        },
        {
          slug: "socket-and-connect",
          title: "Tracking network connections",
          exerciseId: "socket-and-connect",
          codeFile: "3_socket_connect.c",
          contentPath: "chapter-2/socket-and-connect",
        },
      ],
    },
    {
      number: 3,
      slug: "chapter-3",
      title: "Kernel probes",
      exercises: [
        {
          slug: "tcp-connect",
          title: "TCP connections",
          exerciseId: "tcp-connect",
          codeFile: "0_tcp_connect.c",
          contentPath: "chapter-3/tcp-connect",
        },
        {
          slug: "read-http-password",
          title: "Reading TCP packets",
          exerciseId: "read-http-password",
          codeFile: "2_tcp.c",
          contentPath: "chapter-3/read-http-password",
        },
      ],
    },
  ],
};

export function getChapterBySlug(slug: string): ChapterMetadata | undefined {
  return CONTENT_METADATA.chapters.find((c) => c.slug === slug);
}

export function getExerciseByParams(
  chapterSlug: string,
  exerciseSlug: string
): { chapter: ChapterMetadata; exercise: ExerciseMetadata } | undefined {
  const chapter = getChapterBySlug(chapterSlug);
  if (!chapter) return undefined;

  const exercise = chapter.exercises.find((e) => e.slug === exerciseSlug);
  if (!exercise) return undefined;

  return { chapter, exercise };
}

export type FullExMeta = {
  chapter: ChapterMetadata;
  exercise: ExerciseMetadata;
  url: string;
};
export function getAllExercisesFlat(): Array<FullExMeta> {
  return CONTENT_METADATA.chapters.flatMap((chapter) =>
    chapter.exercises.map((exercise) => ({
      chapter,
      exercise,
      url: `/exercises/${chapter.slug}/${exercise.slug}`,
    }))
  );
}

export function getNavigationContext(
  chapterSlug: string,
  exerciseSlug: string
) {
  const allExercises = getAllExercisesFlat();
  const currentIndex = allExercises.findIndex(
    (e) => e.chapter.slug === chapterSlug && e.exercise.slug === exerciseSlug
  );

  if (currentIndex === -1) return null;

  return {
    current: allExercises[currentIndex],
    prev: currentIndex > 0 ? allExercises[currentIndex - 1] : null,
    next:
      currentIndex < allExercises.length - 1
        ? allExercises[currentIndex + 1]
        : null,
  };
}
