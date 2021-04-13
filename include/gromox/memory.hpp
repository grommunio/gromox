#pragma once
template<typename T, typename D> struct unique_proxy {
	public:
	unique_proxy(std::unique_ptr<T, D> &a) : u(a), p(u.get()) {}
	~unique_proxy() { u.reset(p); }
	typename std::unique_ptr<T, D>::pointer *operator&() { return &p; }
	unique_proxy &operator~() { u.reset(); return *this; }
	private:
	std::unique_ptr<T, D> &u;
	typename std::unique_ptr<T, D>::pointer p;
};

template<typename T, typename D> unique_proxy<T, D> unique_tie(std::unique_ptr<T, D> &u)
{
	return unique_proxy<T, D>(u);
}
