//! Claims: what is said to be known of the encrypted stream of one entry, and the run of
//! known bytes a search can start from.
//!
//! A position counts from the first byte of the data of an entry: the twelve bytes of the
//! encryption header are positions -12 to -1.

use std::fmt;

use super::set::ByteSet;

/// The most bytes of a run that a search is given: a longer run leaves hardly fewer candidates
/// (section 3.2 of the design).
pub(crate) const RUN_MAX: u64 = 4096;

/// The most searches one run may stand for: the product of the alternatives of its bytes.
pub(crate) const ALTERNATIVES_MAX: u64 = 4096;

/// The fewest bytes a search starts from.
pub(crate) const RUN_MIN: u64 = 8;

/// How sure a claim is. The order is that of the plan: a sure claim before a guess.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) enum Certainty {
    /// One of several things that may be true.
    Guess,
    /// True of most files of this kind.
    Likely,
    /// Follows from the entry, given that its writer behaves as its kind does.
    Derived,
    /// True of this entry if the archive is not damaged.
    Certain,
}

impl Certainty {
    /// The word a plan and a report use.
    #[must_use]
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::Guess => "guess",
            Self::Likely => "likely",
            Self::Derived => "derived",
            Self::Certain => "certain",
        }
    }
}

impl fmt::Display for Certainty {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Where a claim comes from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub(crate) enum Origin {
    /// The packing method: the form a packed stream has whatever was packed.
    Method,
    /// The name of the entry: the type of file it says.
    Name,
    /// The directory: a copy of the entry that is not encrypted, or a file the tool carries.
    Directory,
    /// The user: a file, a folder, an archive or bytes given on the command line.
    User,
}

impl Origin {
    /// The word of the JSON events.
    #[must_use]
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::Method => "method",
            Self::Name => "name",
            Self::Directory => "directory",
            Self::User => "user",
        }
    }
}

/// What is known of a stretch of a stream.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Cells {
    /// Known bytes.
    Bytes(Vec<u8>),
    /// A set of values for each byte.
    Sets(Vec<ByteSet>),
    /// The same set for a count of bytes: a class.
    Fill(ByteSet, u64),
}

impl Cells {
    /// How many bytes the stretch has.
    #[must_use]
    pub(crate) fn len(&self) -> u64 {
        match self {
            Self::Bytes(bytes) => bytes.len() as u64,
            Self::Sets(sets) => sets.len() as u64,
            Self::Fill(_, len) => *len,
        }
    }

    /// What is known of the byte at `index` of the stretch.
    #[must_use]
    pub(crate) fn get(&self, index: u64) -> Option<ByteSet> {
        let at = usize::try_from(index).ok()?;
        match self {
            Self::Bytes(bytes) => bytes.get(at).map(|&byte| ByteSet::of(byte)),
            Self::Sets(sets) => sets.get(at).copied(),
            Self::Fill(set, len) => (index < *len).then_some(*set),
        }
    }

    /// The bytes `from` to `until - 1` of the stretch.
    #[must_use]
    fn slice(&self, from: u64, until: u64) -> Self {
        let range = usize::try_from(from).unwrap_or(usize::MAX)..usize::try_from(until).unwrap_or(usize::MAX);
        match self {
            Self::Bytes(bytes) => Self::Bytes(bytes.get(range).unwrap_or_default().to_vec()),
            Self::Sets(sets) => Self::Sets(sets.get(range).unwrap_or_default().to_vec()),
            Self::Fill(set, len) => Self::Fill(*set, until.min(*len).saturating_sub(from)),
        }
    }

    /// What both stretches say of the same `len` bytes, the one from `a` on and the other from
    /// `b` on. `None` when they contradict each other in a byte.
    fn both(&self, a: u64, other: &Self, b: u64, len: u64) -> Option<Self> {
        if let (Self::Fill(left, _), Self::Fill(right, _)) = (self, other) {
            let set = left.intersect(*right);
            return (set != ByteSet::NONE).then_some(Self::Fill(set, len));
        }
        let sets: Vec<ByteSet> = (0..len).map(|i| Some(self.get(a + i)?.intersect(other.get(b + i)?))).collect::<Option<_>>()?;
        if sets.contains(&ByteSet::NONE) {
            return None;
        }
        Some(sets.iter().map(|set| set.only()).collect::<Option<Vec<u8>>>().map_or(Self::Sets(sets), Self::Bytes))
    }
}

/// A stretch of a stream with what is known of it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Piece {
    /// The position of its first byte.
    pub at: i64,
    /// What is known from there on.
    pub cells: Cells,
}

impl Piece {
    /// The position behind its last byte.
    #[must_use]
    pub(crate) fn end(&self) -> i64 {
        self.at.saturating_add_unsigned(self.cells.len())
    }
}

/// One way the stream of an entry may be: pieces in rising order that do not overlap. What
/// lies between them is a hole, of which nothing is known.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub(crate) struct Form {
    pieces: Vec<Piece>,
}

impl Form {
    /// A form that says nothing.
    #[must_use]
    pub(crate) const fn new() -> Self {
        Self { pieces: Vec::new() }
    }

    /// A form of known bytes at one position.
    #[must_use]
    pub(crate) fn bytes(at: i64, bytes: &[u8]) -> Self {
        let mut form = Self::new();
        let _ = form.add(at, Cells::Bytes(bytes.to_vec()));
        form
    }

    /// The pieces, in rising order.
    #[must_use]
    pub(crate) fn pieces(&self) -> &[Piece] {
        &self.pieces
    }

    /// Whether the form says nothing.
    #[must_use]
    pub(crate) const fn is_empty(&self) -> bool {
        self.pieces.is_empty()
    }

    /// Add what is known of a stretch. Where the form already says something of a byte, both
    /// have to hold. `false`, and the form as it was, when they contradict each other.
    #[must_use]
    pub(crate) fn add(&mut self, at: i64, cells: Cells) -> bool {
        let len = cells.len();
        if len == 0 {
            return true;
        }
        let end = at.saturating_add_unsigned(len);
        let first = self.pieces.partition_point(|piece| piece.end() <= at);
        let last = self.pieces.partition_point(|piece| piece.at < end);
        if first == last {
            // nothing is said of the stretch yet
            self.pieces.insert(first, Piece { at, cells });
            self.join();
            return true;
        }
        let mut merged = Vec::new();
        let mut cursor = at;
        for old in self.pieces.get(first..last).unwrap_or_default() {
            if old.at < at {
                merged.push(Piece { at: old.at, cells: old.cells.slice(0, at.abs_diff(old.at)) });
            }
            if cursor < old.at {
                merged.push(Piece { at: cursor, cells: cells.slice(cursor.abs_diff(at), old.at.abs_diff(at)) });
                cursor = old.at;
            }
            let until = old.end().min(end);
            let Some(both) = old.cells.both(cursor.abs_diff(old.at), &cells, cursor.abs_diff(at), until.abs_diff(cursor)) else { return false };
            merged.push(Piece { at: cursor, cells: both });
            cursor = until;
            if old.end() > end {
                merged.push(Piece { at: end, cells: old.cells.slice(end.abs_diff(old.at), old.cells.len()) });
            }
        }
        if cursor < end {
            merged.push(Piece { at: cursor, cells: cells.slice(cursor.abs_diff(at), len) });
        }
        drop(self.pieces.splice(first..last, merged));
        self.join();
        true
    }

    /// Make one piece of every two that touch and are of one kind, so that two forms that say
    /// the same are the same.
    fn join(&mut self) {
        let mut joined: Vec<Piece> = Vec::with_capacity(self.pieces.len());
        for piece in self.pieces.drain(..) {
            match joined.last_mut() {
                Some(last) if last.end() == piece.at => match (&mut last.cells, piece.cells) {
                    (Cells::Bytes(so_far), Cells::Bytes(more)) => so_far.extend(more),
                    (Cells::Sets(so_far), Cells::Sets(more)) => so_far.extend(more),
                    (Cells::Fill(set, len), Cells::Fill(other, more)) if *set == other => *len += more,
                    (_, cells) => joined.push(Piece { at: piece.at, cells }),
                },
                _ => joined.push(piece),
            }
        }
        self.pieces = joined;
    }

    /// The form that says what this one and `other` say. `None` when they contradict each
    /// other.
    #[must_use]
    pub(crate) fn merged(&self, other: &Self) -> Option<Self> {
        let mut form = self.clone();
        other.pieces.iter().all(|piece| form.add(piece.at, piece.cells.clone())).then_some(form)
    }

    /// What is known of the byte at a position. `None` for a hole.
    #[must_use]
    pub(crate) fn get(&self, at: i64) -> Option<ByteSet> {
        let index = self.pieces.partition_point(|piece| piece.end() <= at);
        let piece = self.pieces.get(index).filter(|piece| piece.at <= at)?;
        piece.cells.get(at.abs_diff(piece.at))
    }

    /// The form moved by a count of positions.
    #[must_use]
    pub(crate) fn shifted(&self, by: i64) -> Self {
        Self { pieces: self.pieces.iter().map(|piece| Piece { at: piece.at.saturating_add(by), cells: piece.cells.clone() }).collect() }
    }

    /// What the form says of the positions `from` to `until - 1`.
    #[must_use]
    pub(crate) fn clipped(&self, from: i64, until: i64) -> Self {
        let pieces = self
            .pieces
            .iter()
            .filter_map(|piece| {
                let (start, end) = (piece.at.max(from), piece.end().min(until));
                (start < end).then(|| Piece { at: start, cells: piece.cells.slice(start.abs_diff(piece.at), end.abs_diff(piece.at)) })
            })
            .collect();
        Self { pieces }
    }

    /// The first position the form says something of, and the one behind the last.
    #[must_use]
    pub(crate) fn span(&self) -> Option<(i64, i64)> {
        Some((self.pieces.first()?.at, self.pieces.last()?.end()))
    }

    /// How many bytes of the form are known exactly.
    #[cfg(test)]
    #[must_use]
    pub(crate) fn known(&self) -> u64 {
        self.stretches().iter().map(|&(_, len)| len).sum()
    }

    /// What the form is worth as a filter, in bits (section 5.2 of the design).
    #[must_use]
    pub(crate) fn bits(&self) -> f64 {
        self.pieces
            .iter()
            .map(|piece| match &piece.cells {
                Cells::Bytes(bytes) => 8.0 * count_as_f64(bytes.len() as u64),
                Cells::Sets(sets) => sets.iter().map(|set| set.bits()).sum(),
                Cells::Fill(set, len) => set.bits() * count_as_f64(*len),
            })
            .sum()
    }

    /// The stretches of bytes that are known exactly, each as its first position and its
    /// length, in rising order. Pieces that touch are one stretch.
    #[must_use]
    pub(crate) fn stretches(&self) -> Vec<(i64, u64)> {
        let mut stretches: Vec<(i64, u64)> = Vec::new();
        let mut push = |at: i64, len: u64| match stretches.last_mut() {
            Some((start, so_far)) if start.saturating_add_unsigned(*so_far) == at => *so_far += len,
            _ => stretches.push((at, len)),
        };
        for piece in &self.pieces {
            match &piece.cells {
                Cells::Bytes(bytes) => push(piece.at, bytes.len() as u64),
                Cells::Fill(set, len) if set.len() == 1 => push(piece.at, *len),
                Cells::Fill(..) => {},
                Cells::Sets(sets) => {
                    for (at, set) in (piece.at..).zip(sets) {
                        if set.len() == 1 {
                            push(at, 1);
                        }
                    }
                },
            }
        }
        stretches
    }

    /// The run a search of this form starts from: the stretch for which the count of searches
    /// times the count of candidates is smallest (section 4.1 of the design).
    ///
    /// A run is at least eight positions. A byte with alternatives inside it multiplies the
    /// searches by their count. A hole, a byte of which nothing is known, multiplies them by
    /// 256 and is taken only when `deep` is set, and only one of them. `None` when the form
    /// has no such stretch.
    #[must_use]
    pub(crate) fn best_run(&self, deep: bool) -> Option<Run> {
        let mut best: Option<Run> = None;
        for (at, len) in self.stretches() {
            let mut run = Run { at, len, searches: 1, holes: 0 };
            loop {
                if run.len >= RUN_MIN && best.as_ref().is_none_or(|so_far| run.cost() < so_far.cost()) {
                    best = Some(run.capped());
                }
                // one more position on either side, with the known bytes that follow it
                let wider = [self.grown(&run, false, deep), self.grown(&run, true, deep)].into_iter().flatten().min_by(|a, b| a.cost().total_cmp(&b.cost()));
                match wider {
                    Some(wider) if wider.searches <= ALTERNATIVES_MAX && (run.len < RUN_MIN || wider.cost() < run.cost()) => run = wider,
                    _ => break,
                }
            }
        }
        best
    }

    /// `run` with the position in front of it, or behind it, and every known byte that follows
    /// from there. `None` when that position is a hole and holes are not taken.
    fn grown(&self, run: &Run, behind: bool, deep: bool) -> Option<Run> {
        let position = if behind { run.end() } else { run.at.checked_sub(1)? };
        let (alternatives, holes) = match self.get(position) {
            Some(set) => (u64::from(set.len()), run.holes),
            None if deep && run.holes == 0 && position >= -12 => (256, 1),
            None => return None,
        };
        let mut grown = Run { at: run.at.min(position), len: run.len + 1, searches: run.searches.saturating_mul(alternatives), holes };
        loop {
            let next = if behind { grown.end() } else { grown.at - 1 };
            if self.get(next).is_none_or(|set| set.len() != 1) {
                return Some(grown);
            }
            grown.at = grown.at.min(next);
            grown.len += 1;
        }
    }
}

/// A count as a number for arithmetic on estimates. Counts here are far below 2^52, where the
/// conversion is exact.
#[must_use]
pub(crate) fn count_as_f64(count: u64) -> f64 {
    f64::from(u32::try_from(count >> 32).unwrap_or(u32::MAX)) * 4_294_967_296.0 + f64::from(u32::try_from(count & 0xffff_ffff).unwrap_or(u32::MAX))
}

/// A stretch of a form that a search starts from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Run {
    /// The position of its first byte.
    pub at: i64,
    /// How many bytes it has.
    pub len: u64,
    /// How many searches it stands for: one, or the product of the alternatives of its bytes.
    pub searches: u64,
    /// How many of its bytes are holes.
    pub holes: u32,
}

impl Run {
    /// The position behind its last byte.
    #[must_use]
    pub(crate) const fn end(&self) -> i64 {
        self.at.saturating_add_unsigned(self.len)
    }

    /// What the run costs, in candidates: the searches times what a run of its length leaves.
    #[must_use]
    pub(crate) fn cost(&self) -> f64 {
        count_as_f64(self.searches) * expected_candidates(self.len)
    }

    /// The run cut down to the most bytes a search is given.
    #[must_use]
    fn capped(self) -> Self {
        Self { len: self.len.min(RUN_MAX), ..self }
    }
}

/// How many candidates a run of `len` bytes leaves, from the counts of section 3.2 of the
/// design. Between two measured lengths the count is taken on a straight line in the
/// logarithms of both. It orders runs; the plan counts the candidates of the run it takes.
#[must_use]
pub(crate) fn expected_candidates(len: u64) -> f64 {
    const MEASURED: [(u32, f64); 18] = [
        (8, 4_194_304.0),
        (9, 3_500_000.0),
        (10, 2_200_000.0),
        (11, 1_800_000.0),
        (12, 1_418_713.0),
        (13, 1_213_288.0),
        (14, 1_056_075.0),
        (16, 849_652.0),
        (20, 584_306.0),
        (24, 443_940.0),
        (32, 321_241.0),
        (48, 198_704.0),
        (64, 145_208.0),
        (128, 68_268.0),
        (256, 32_997.0),
        (512, 15_192.0),
        (1024, 8_032.0),
        (4096, 2_990.0),
    ];
    let len = u32::try_from(len.min(RUN_MAX)).unwrap_or(4096);
    if len < 8 {
        // a byte that is missing costs 256 searches of a run of eight
        return 4_194_304.0 * 256_f64.powi(i32::try_from(8 - len).unwrap_or(8));
    }
    let mut below: (u32, f64) = (8, 4_194_304.0);
    for (length, count) in MEASURED {
        if length == len {
            return count;
        }
        if length > len {
            let share = (f64::from(len).ln() - f64::from(below.0).ln()) / (f64::from(length).ln() - f64::from(below.0).ln());
            return (below.1.ln() + share * (count.ln() - below.1.ln())).exp();
        }
        below = (length, count);
    }
    below.1
}

/// What is said to be known of one entry. One of its forms holds, if the claim is true.
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct Claim {
    /// Where it comes from.
    pub origin: Origin,
    /// How sure it is.
    pub certainty: Certainty,
    /// What it is, in the words of a plan: "signature of a PNG file".
    pub what: String,
    /// The ways the stream may be, the most likely first.
    pub forms: Vec<Form>,
}

impl Claim {
    /// A claim with one form.
    #[must_use]
    pub(crate) fn new(origin: Origin, certainty: Certainty, what: impl Into<String>, form: Form) -> Self {
        Self { origin, certainty, what: what.into(), forms: vec![form] }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn form(pieces: &[(i64, Cells)]) -> Form {
        let mut form = Form::new();
        for (at, cells) in pieces {
            assert!(form.add(*at, cells.clone()));
        }
        form
    }

    #[test]
    fn a_form_keeps_its_pieces_in_order_and_answers_for_every_position() {
        let form = form(&[(10, Cells::Bytes(b"world".to_vec())), (0, Cells::Bytes(b"hello".to_vec())), (5, Cells::Fill(ByteSet::text(), 3))]);
        assert_eq!(form.pieces().iter().map(|piece| piece.at).collect::<Vec<_>>(), [0, 5, 10]);
        assert_eq!(form.get(0), Some(ByteSet::of(b'h')));
        assert_eq!(form.get(4), Some(ByteSet::of(b'o')));
        assert_eq!(form.get(6), Some(ByteSet::text()));
        assert_eq!((form.get(8), form.get(9), form.get(-1), form.get(15)), (None, None, None, None));
        assert_eq!(form.get(14), Some(ByteSet::of(b'd')));
        assert_eq!(form.span(), Some((0, 15)));
        assert_eq!(form.known(), 10);
        assert_eq!(form.stretches(), [(0, 5), (10, 5)]);
        assert!((form.bits() - (80.0 + 3.0 * ByteSet::text().bits())).abs() < 1e-9);
    }

    #[test]
    fn what_two_claims_say_of_one_byte_has_to_hold_together() {
        // a class and known bytes over the same stretch: the bytes, when they are of the class
        let mut text = form(&[(0, Cells::Fill(ByteSet::text(), 8))]);
        assert!(text.add(2, Cells::Bytes(b"abcdefghij".to_vec())));
        assert_eq!(text.stretches(), [(2, 10)]);
        assert_eq!((text.get(1), text.get(2), text.get(11), text.get(12)), (Some(ByteSet::text()), Some(ByteSet::of(b'a')), Some(ByteSet::of(b'j')), None));

        // a byte that is not of the class contradicts it, and the form stays as it was
        let before = text.clone();
        assert!(!text.add(0, Cells::Bytes(vec![0x00])));
        assert_eq!(text, before);
        assert!(!text.add(2, Cells::Bytes(b"b".to_vec())));
        assert!(text.add(2, Cells::Bytes(b"a".to_vec())));
        assert_eq!(text, before);

        // alternatives narrow each other
        let mut sets = form(&[(0, Cells::Sets(vec![ByteSet::from_values([1, 2, 3])]))]);
        assert!(sets.add(0, Cells::Sets(vec![ByteSet::from_values([3, 4])])));
        assert_eq!(sets.get(0), Some(ByteSet::of(3)));
        assert_eq!(sets.stretches(), [(0, 1)]);

        // a piece that covers several, with holes between them
        let mut wide = form(&[(0, Cells::Bytes(vec![1, 2])), (4, Cells::Bytes(vec![5, 6])), (8, Cells::Bytes(vec![9]))]);
        assert!(wide.add(1, Cells::Fill(ByteSet::ascii(), 7)));
        assert_eq!(wide.stretches(), [(0, 2), (4, 2), (8, 1)]);
        assert_eq!((wide.get(2), wide.get(3), wide.get(6), wide.get(7)), (Some(ByteSet::ascii()), Some(ByteSet::ascii()), Some(ByteSet::ascii()), Some(ByteSet::ascii())));
        assert_eq!(wide.merged(&form(&[(8, Cells::Bytes(vec![10]))])), None);
        assert!(wide.merged(&form(&[(8, Cells::Bytes(vec![9, 10]))])).is_some_and(|both| both.known() == 6));
    }

    #[test]
    fn a_form_is_moved_and_cut() {
        let form = form(&[(0, Cells::Bytes(vec![1, 2, 3, 4])), (10, Cells::Fill(ByteSet::text(), 100))]);
        assert_eq!(form.shifted(5).span(), Some((5, 115)));
        let cut = form.clipped(2, 20);
        assert_eq!((cut.span(), cut.get(1), cut.get(2), cut.get(19), cut.get(20)), (Some((2, 20)), None, Some(ByteSet::of(3)), Some(ByteSet::text()), None));
        assert!(form.clipped(4, 10).is_empty());
    }

    #[test]
    fn the_run_is_the_longest_stretch_of_known_bytes() {
        let form = form(&[(-1, Cells::Bytes(vec![0xa9])), (0, Cells::Bytes(b"<?xml version=\"1.0\"".to_vec())), (40, Cells::Bytes(b"0123456789".to_vec()))]);
        assert_eq!(form.best_run(false), Some(Run { at: -1, len: 20, searches: 1, holes: 0 }));
        // seven bytes in a row are no run, and no eighth is made up
        assert_eq!(Form::bytes(0, b"1234567").best_run(false), None);
        assert_eq!(Form::bytes(0, b"12345678").best_run(false), Some(Run { at: 0, len: 8, searches: 1, holes: 0 }));
        // a run is cut at what a search is given
        assert_eq!(Form::bytes(3, &[0; 10_000]).best_run(false), Some(Run { at: 3, len: 4096, searches: 1, holes: 0 }));
    }

    #[test]
    fn a_byte_with_alternatives_is_taken_into_the_run_when_that_is_cheaper() {
        // two stretches of six with a byte of two alternatives between them: thirteen in two searches
        let joined = form(&[(0, Cells::Bytes(b"GIF8".to_vec())), (4, Cells::Sets(vec![ByteSet::from_values([b'7', b'9'])])), (5, Cells::Bytes(b"a\x10\x00\x10\x00\xf7\x00\x00".to_vec()))]);
        assert_eq!(joined.best_run(false), Some(Run { at: 0, len: 13, searches: 2, holes: 0 }));
        // a long stretch is not made longer through a class: 98 searches cost more than they save
        let long = form(&[(0, Cells::Bytes(vec![7; 12])), (12, Cells::Fill(ByteSet::text(), 50))]);
        assert_eq!(long.best_run(false), Some(Run { at: 0, len: 12, searches: 1, holes: 0 }));
        // seven known bytes and one of a class: a run of eight in 98 searches, since there is no other
        let short = form(&[(0, Cells::Bytes(vec![7; 7])), (7, Cells::Fill(ByteSet::text(), 50))]);
        assert_eq!(short.best_run(false), Some(Run { at: 0, len: 8, searches: 98, holes: 0 }));
    }

    #[test]
    fn a_hole_is_taken_into_a_run_only_when_asked_and_only_once() {
        let seven = Form::bytes(0, b"Dear M");
        let with_check = seven.merged(&Form::bytes(-1, &[0x5a])).unwrap();
        assert_eq!(with_check.best_run(false), None);
        assert_eq!(with_check.best_run(true), Some(Run { at: -2, len: 8, searches: 256, holes: 1 }));
        // six in a row would take two holes: left out
        assert_eq!(seven.best_run(true), None);
        // a byte of which three low bits are known costs 32 searches where a hole costs 256
        let bits = with_check.merged(&form(&[(6, Cells::Sets(vec![ByteSet::low_bits(5, 3)]))])).unwrap();
        assert_eq!(bits.best_run(false), Some(Run { at: -1, len: 8, searches: 32, holes: 0 }));
        // a hole joins two stretches when that leaves fewer candidates in all
        let apart = form(&[(0, Cells::Bytes(vec![1; 4])), (5, Cells::Bytes(vec![2; 4]))]);
        assert_eq!((apart.best_run(false), apart.best_run(true)), (None, Some(Run { at: 0, len: 9, searches: 256, holes: 1 })));
    }

    #[test]
    fn the_expected_count_of_candidates_falls_with_the_length_of_the_run() {
        assert!((expected_candidates(8) - 4_194_304.0).abs() < 1.0);
        assert!((expected_candidates(12) - 1_418_713.0).abs() < 1.0);
        assert!((expected_candidates(4096) - 2_990.0).abs() < 1.0 && (expected_candidates(1 << 20) - 2_990.0).abs() < 1.0);
        let mut last = f64::MAX;
        for len in 8..5000 {
            let count = expected_candidates(len);
            assert!(count <= last, "{len}");
            last = count;
        }
        // between 14 and 16 measured bytes
        assert!((849_652.0..1_056_075.0).contains(&expected_candidates(15)));
        assert!((expected_candidates(7) / expected_candidates(8) - 256.0).abs() < 1e-9);
        assert_eq!(count_as_f64(u64::from(u32::MAX) + 5).to_bits(), 4_294_967_300.0_f64.to_bits());
    }

    #[test]
    fn certainty_is_ordered_as_a_plan_orders_it() {
        assert!(Certainty::Certain > Certainty::Derived && Certainty::Derived > Certainty::Likely && Certainty::Likely > Certainty::Guess);
        assert_eq!([Certainty::Certain, Certainty::Derived, Certainty::Likely, Certainty::Guess].map(Certainty::as_str), ["certain", "derived", "likely", "guess"]);
        assert_eq!(Origin::User.as_str(), "user");
    }
}
