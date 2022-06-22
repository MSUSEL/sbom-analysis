

pub struct LongestZip<L, R, IL: Iterator<Item=L>, IR: Iterator<Item=R>> {
    left: IL,
    right: IR,
}

pub fn zip_longest<L, R, IL: Iterator<Item=L>, IR: Iterator<Item=R>>(left: IL, right: IR) -> LongestZip<L, R, IL, IR> {
    LongestZip {
        left,
        right,
    }
}

impl<L, R, IL: Iterator<Item=L>, IR: Iterator<Item=R>> Iterator for LongestZip<L, R, IL, IR> {
    type Item = (Option<L>, Option<R>);

    fn next(&mut self) -> Option<Self::Item> {
        match (self.left.next(), self.right.next()) {
            (None, None) => None,
            (a, b) => Some((a, b)),
        }
    }
}